#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Command } from 'commander';
import { getProvider, getDefaultProvider } from './providers/index.js';
import { SessionCache } from './cache.js';
import { createKeyId, sanitizeError, clearString } from './security.js';
import { loadConfig } from './config.js';
import type { VhsmConfig } from './types.js';

const program = new Command();

program
  .name('vhsm')
  .description('Virtual HSM - Secure dotenvx wrapper with pluggable key decryption')
  .version('0.1.0');

program
  .command('run')
  .description('Decrypt dotenvx private key and run a command with dotenvx')
  .argument('<command...>', 'Command to run with dotenvx')
  .option('-k, --key <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Key decryption provider to use', 'password')
  .option('--password <pass>', 'Password/passphrase for decryption (for testing)')
  .option('--no-cache', 'Disable session caching')
  .option('--cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  .action(async (command: string[], options) => {
    try {
      await runCommand(command, options);
    } catch (error) {
      const sanitized = sanitizeError(error);
      console.error(`Error: ${sanitized.message}`);
      process.exit(1);
    }
  });

program
  .command('encrypt')
  .description('Encrypt a dotenvx private key with a password')
  .argument('[key-file]', 'Path to plaintext private key file', '.env.keys')
  .option('-o, --output <path>', 'Output path for encrypted key', '.env.keys.encrypted')
  .option('--password <pass>', 'Password/passphrase for encryption (for testing)')
  .option('--no-delete', 'Do not delete the original .env.keys file after encryption')
  .action(async (keyFile: string, options) => {
    try {
      const inputFile = keyFile || '.env.keys';
      // --no-delete sets options.delete to false, so we delete when delete is not false
      const shouldDelete = options.delete !== false;
      await encryptKey(inputFile, options.output, options.password, shouldDelete);
    } catch (error) {
      const sanitized = sanitizeError(error);
      console.error(`Error: ${sanitized.message}`);
      process.exit(1);
    }
  });

program
  .command('clear-cache')
  .description('Clear the session cache')
  .action(() => {
    globalCache.clear();
    console.log('Cache cleared');
  });

// Global session cache instance
const globalCache = new SessionCache();

async function runCommand(command: string[], options: {
  key?: string;
  provider?: string;
  password?: string;
  cache?: boolean;
  cacheTimeout?: string;
}) {
  const config = loadConfig();
  
  // Determine provider
  const providerName = options.provider || config.provider || 'password';
  const provider = providerName === 'password' 
    ? getDefaultProvider() 
    : getProvider(providerName);

  // Load encrypted key
  const keyPath = options.key || '.env.keys.encrypted';
  let encryptedKeyContent: string;
  
  try {
    encryptedKeyContent = readFileSync(keyPath, 'utf-8').trim();
  } catch (error) {
    throw new Error(`Failed to read encrypted key file: ${keyPath}. ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  if (!encryptedKeyContent) {
    throw new Error('Encrypted key file is empty');
  }

  // Extract the encrypted data from the file
  // Handle both formats:
  // - New format: ENCAPSULATED_KEY=encrypted:...
  // - Old format: raw encrypted data (salt:iv:tag:encryptedData)
  let encryptedKey: string;
  if (encryptedKeyContent.startsWith('ENCAPSULATED_KEY=encrypted:')) {
    // New format: extract the encrypted part after "encrypted:"
    encryptedKey = encryptedKeyContent.substring('ENCAPSULATED_KEY=encrypted:'.length);
  } else {
    // Old format: use the content as-is
    encryptedKey = encryptedKeyContent;
  }

  // Check cache
  const keyId = createKeyId(encryptedKey);
  const enableCache = options.cache !== false && (config.enableCache !== false);
  const cacheTimeout = options.cacheTimeout 
    ? parseInt(options.cacheTimeout, 10) 
    : (config.cacheTimeout || 3600000);

  let decryptedKey: string | null = null;

  if (enableCache) {
    globalCache.cleanup();
    decryptedKey = globalCache.get(keyId);
  }

  // Decrypt if not cached
  if (!decryptedKey) {
    try {
      // Pass password to provider if provided
      if (options.password && provider.name === 'password') {
        decryptedKey = await (provider as any).decrypt(encryptedKey, options.password);
      } else {
        decryptedKey = await provider.decrypt(encryptedKey);
      }
      
      // Extract just the DOTENV_PRIVATE_KEY value if the decrypted content is the full file
      // This handles both old format (full file) and new format (just the key value)
      if (decryptedKey && decryptedKey.includes('DOTENV_PRIVATE_KEY=')) {
        const lines = decryptedKey.split('\n');
        const keyLine = lines.find(line => line.trim().startsWith('DOTENV_PRIVATE_KEY='));
        if (keyLine) {
          const keyValue = keyLine.split('=').slice(1).join('=').trim();
          if (keyValue) {
            decryptedKey = keyValue;
          }
        }
      }
      
      // Cache the decrypted key
      if (enableCache && decryptedKey) {
        globalCache.set(keyId, decryptedKey, cacheTimeout);
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'DecryptionError') {
        throw error;
      }
      throw new Error('Failed to decrypt private key');
    }
  }

  if (!decryptedKey) {
    throw new Error('Failed to obtain decrypted key');
  }

  // Prepare environment with decrypted key
  const env = {
    ...process.env,
    DOTENV_PRIVATE_KEY: decryptedKey,
  };

  // Spawn dotenvx run with the command
  const dotenvxArgs = ['run', ...command];
  const child = spawn('dotenvx', dotenvxArgs, {
    stdio: 'inherit',
    env,
    shell: process.platform === 'win32',
  });

  // Clear decrypted key from this process's memory after spawning
  // Note: The child process will have its own copy
  setTimeout(() => {
    clearString(decryptedKey!);
  }, 100);

  // Wait for child process to exit
  const exitCode = await new Promise<number>((resolve) => {
    child.on('exit', (code) => {
      resolve(code ?? 0);
    });
    
    child.on('error', (error) => {
      console.error(`Failed to spawn dotenvx: ${error.message}`);
      resolve(1);
    });
  });

  process.exit(exitCode);
}

async function encryptKey(keyFile: string, outputPath: string, providedPassword?: string, shouldDelete: boolean = true) {
  const { encryptKeyWithPassword } = await import('./providers/password.js');
  const inquirer = (await import('inquirer')).default;

  // Read plaintext key file
  let keyFileContent: string;
  try {
    keyFileContent = readFileSync(keyFile, 'utf-8');
  } catch (error) {
    throw new Error(`Failed to read key file: ${keyFile}`);
  }

  // Extract just the DOTENV_PRIVATE_KEY value from the file
  // The .env.keys file may contain comments, so we need to find the actual key line
  const lines = keyFileContent.split('\n');
  const keyLine = lines.find(line => line.trim().startsWith('DOTENV_PRIVATE_KEY='));
  
  if (!keyLine) {
    throw new Error('No DOTENV_PRIVATE_KEY found in key file');
  }

  // Extract the value after the = sign
  const keyValue = keyLine.split('=').slice(1).join('=').trim();
  
  if (!keyValue) {
    throw new Error('DOTENV_PRIVATE_KEY value is empty');
  }

  const plaintextKey = keyValue;

  let password: string;
  let confirmPassword: string = '';

  if (providedPassword) {
    // Use provided password (for testing)
    password = providedPassword;
    if (password.length < 8) {
      throw new Error('Passphrase must be at least 8 characters');
    }
  } else {
    // Prompt for password
    const prompts = await inquirer.prompt([
      {
        type: 'password',
        name: 'password',
        message: 'Enter passphrase to encrypt the key:',
        mask: '*',
        validate: (input: string) => {
          if (!input || input.length < 8) {
            return 'Passphrase must be at least 8 characters';
          }
          return true;
        },
      },
      {
        type: 'password',
        name: 'confirmPassword',
        message: 'Confirm passphrase:',
        mask: '*',
        validate: (input: string, answers: any) => {
          if (input !== answers.password) {
            return 'Passphrases do not match';
          }
          return true;
        },
      },
    ]);
    password = prompts.password;
    confirmPassword = prompts.confirmPassword;
  }

  // Encrypt
  const encrypted = encryptKeyWithPassword(plaintextKey, password);

  // Format as ENCAPSULATED_KEY=encrypted:...
  const encapsulatedKey = `ENCAPSULATED_KEY=encrypted:${encrypted}`;

  // Write to file
  const { writeFileSync, unlinkSync } = await import('node:fs');
  writeFileSync(outputPath, encapsulatedKey, { mode: 0o600 }); // Read/write for owner only

  console.log(`Encrypted key written to: ${outputPath}`);
  console.log('Make sure to secure this file and never commit it to version control.');
  
  // Delete the original .env.keys file if requested
  if (shouldDelete) {
    try {
      unlinkSync(keyFile);
      console.log(`Deleted original key file: ${keyFile}`);
    } catch (error) {
      console.warn(`Warning: Could not delete original key file: ${keyFile}`);
    }
  }
  
  // Note: JavaScript strings are immutable, so we can't actually clear them from memory
  // The passwords will be garbage collected when they go out of scope
}

// Parse CLI arguments
program.parse();

