#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { Command } from 'commander';
import { getProvider, getDefaultProvider, listProviders } from './providers/index.js';
import { SessionCache } from './cache.js';
import { createKeyId, sanitizeError, clearString } from './security.js';
import { loadConfig } from './config.js';
import type { VhsmConfig } from './types.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { name?: string; version?: string; description?: string };
const resolvedDotenvxBin = resolveDotenvxBin();
let warnedAboutGlobalDotenvx = false;

const program = new Command();

function resolveDotenvxBin(): string | null {
  try {
    const pkgPath = require.resolve('@dotenvx/dotenvx/package.json');
    const pkgDir = dirname(pkgPath);
    const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const binField =
      typeof pkgJson.bin === 'string'
        ? pkgJson.bin
        : pkgJson.bin?.dotenvx;
    if (binField) {
      return join(pkgDir, binField);
    }
  } catch (error) {
    // ignore - fallback will use global command
  }
  return null;
}

function spawnDotenvx(args: string[], options: Parameters<typeof spawn>[2]) {
  if (resolvedDotenvxBin) {
    return spawn(process.execPath, [resolvedDotenvxBin, ...args], {
      ...options,
      shell: false,
    });
  }

  if (!warnedAboutGlobalDotenvx) {
    console.warn('⚠️  Local @dotenvx/dotenvx not found. Falling back to global "dotenvx" command.');
    warnedAboutGlobalDotenvx = true;
  }

  return spawn('dotenvx', args, options);
}

program
  .name(pkg.name || 'vhsm')
  .description(pkg.description || 'Virtual HSM - Secure dotenvx wrapper with pluggable key decryption')
  .version(pkg.version || '0.0.0');

program
  .command('run')
  .description('Decrypt dotenvx private key and run a command with dotenvx')
  .argument('<command...>', 'Command to run with dotenvx')
  .option('-ef, --encrypted-key <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Key decryption provider to use', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for decryption (for testing)')
  .option('-nc, --no-cache', 'Disable session caching')
  .option('-ct, --cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  // Pass-through options for dotenvx run
  .option('-e, --env <strings...>', 'Environment variable(s) set as string (example: "HELLO=World")')
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  // .option('-fk, --env-keys-file <path>', 'Path to your .env.keys file') // excluded since ef is used instead
  // .option('-fv, --env-vault-file <paths...>', 'Path(s) to your .env.vault file(s)') // deprecated
  .option('-o, --overload', 'Override existing env variables')
  .option('--strict', 'Process.exit(1) on any errors')
  .option('--convention <name>', 'Load a .env convention (available: nextjs, flow)')
  .option('--ignore <errorCodes...>', 'Error code(s) to ignore (example: MISSING_ENV_FILE)')
  .option('--ops-off', 'Disable dotenvx-ops features')
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
  .description('Encrypt a dotenvx private key')
  .option('-o, --output <path>', 'Output path for encrypted key', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Encryption provider to use (password, dpapi, fido2, tpm2)', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for encryption (for testing, password/tpm2 providers only)')
  .option('-nd, --no-delete', 'Do not delete the original .env.keys file after encryption')
  // Pass-through options for dotenvx encrypt
  .option('-fk, --env-keys-file <path>', 'Path to plaintext private key file', '.env.keys')
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  .option('-k, --key <keys...>', 'Key(s) to encrypt (default: all keys in file)')
  .option('-ek, --exclude-key <excludeKeys...>', 'Key(s) to exclude from encryption (default: none)')
  .action(async (options) => {
    try {
      const inputFile = options.envKeysFile || '.env.keys';
      // --no-delete sets options.delete to false, so we delete when delete is not false
      const shouldDelete = options.delete !== false;
      await encryptKey(inputFile, options.output, options.provider, options.password, shouldDelete, {
        envFile: options.envFile,
        key: options.key,
        excludeKey: options.excludeKey,
      });
      process.exit(0);
    } catch (error) {
      const sanitized = sanitizeError(error);
      console.error(`Error: ${sanitized.message}`);
      process.exit(1);
    }
  });

program
  .command('decrypt')
  .description('Decrypt dotenvx private key and run dotenvx decrypt')
  .option('-ef, --encrypted-key <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Key decryption provider to use', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for decryption (for testing)')
  .option('-nc, --no-cache', 'Disable session caching')
  .option('-ct, --cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  .option('-r, --restore', 'Restore the decrypted key to a .env.keys file')
  .option('-fk, --env-keys-file <path>', 'Output path for restored key file (used with --restore)', '.env.keys')
  // Pass-through options for dotenvx decrypt
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  .option('-k, --key <keys...>', 'Key(s) to decrypt (default: all keys in file)')
  .option('-ek, --exclude-key <excludeKeys...>', 'Key(s) to exclude from decryption (default: none)')
  .action(async (options) => {
    try {
      await decryptCommand(options);
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Load and validate encrypted key file
 */
function loadEncryptedKeyFile(keyPath: string): string {
  try {
    const content = readFileSync(keyPath, 'utf-8').trim();
    if (!content) {
      throw new Error('Encrypted key file is empty');
    }
    return content;
  } catch (error) {
    throw new Error(`Failed to read encrypted key file: ${keyPath}. ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Parse all VHSM_PRIVATE_KEY* entries from encrypted file
 * Supports "encrypted:" (password), "dpapi:", "fido2:", and "tpm2:" prefixes
 */
function parseEncryptedKeys(content: string): Array<{ vhsmKey: string; encryptedValue: string; provider: string }> {
  const keys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }> = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || !trimmed) {
      continue;
    }
    
    // Match VHSM_PRIVATE_KEY[_SUFFIX]=(encrypted|dpapi|fido2|tpm2):...
    const match = /^(VHSM_PRIVATE_KEY[^=]*)=(encrypted|dpapi|fido2|tpm2):(.*)/.exec(trimmed);
    if (match) {
      const providerPrefix = match[2];
      let provider = 'password';
      
      if (providerPrefix === 'dpapi') {
        provider = 'dpapi';
      } else if (providerPrefix === 'fido2') {
        provider = 'fido2';
      } else if (providerPrefix === 'tpm2') {
        provider = 'tpm2';
      }
      
      keys.push({
        vhsmKey: match[1],
        provider,
        encryptedValue: match[3],
      });
    }
  }
  
  return keys;
}

/**
 * Extract suffix from env file name
 * .env → ''
 * .env.local → '_LOCAL'
 * .env.production → '_PRODUCTION'
 */
function getEnvSuffix(envFile: string): string {
  if (envFile === '.env') {
    return '';
  }
  
  const parts = envFile.split('.');
  if (parts.length > 2) {
    return '_' + parts[parts.length - 1].toUpperCase();
  }
  
  return '';
}

/**
 * Convert VHSM key name to DOTENV key name
 * VHSM_PRIVATE_KEY → DOTENV_PRIVATE_KEY
 * VHSM_PRIVATE_KEY_LOCAL → DOTENV_PRIVATE_KEY_LOCAL
 */
function vhsmKeyToDotenvKey(vhsmKey: string): string {
  return vhsmKey.replace('VHSM_', 'DOTENV_');
}

/**
 * Match keys to env files based on suffixes
 */
function matchKeysToEnvFiles(
  envFiles: string[],
  availableKeys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }>
): Array<{ vhsmKey: string; dotenvKey: string; encryptedValue: string; provider: string; envFile: string }> {
  const keysToProcess: Array<{ vhsmKey: string; dotenvKey: string; encryptedValue: string; provider: string; envFile: string }> = [];
  
  for (const envFile of envFiles) {
    const suffix = getEnvSuffix(envFile);
    const vhsmKey = `VHSM_PRIVATE_KEY${suffix}`;
    const dotenvKey = `DOTENV_PRIVATE_KEY${suffix}`;
    
    // Find the matching encrypted key
    const keyEntry = availableKeys.find(k => k.vhsmKey === vhsmKey);
    if (keyEntry) {
      keysToProcess.push({
        vhsmKey,
        dotenvKey,
        encryptedValue: keyEntry.encryptedValue,
        provider: keyEntry.provider,
        envFile,
      });
    } else {
      console.warn(`⚠️  No encrypted key found for ${envFile} (looking for ${vhsmKey})`);
    }
  }
  
  return keysToProcess;
}

/**
 * Decrypt a key with cache support
 */
async function decryptKeyWithCache(
  encryptedValue: string,
  providerName: string,
  password: string | undefined,
  enableCache: boolean,
  cacheTimeout: number,
  keyName?: string
): Promise<string> {
  const keyId = createKeyId(encryptedValue);
  let decryptedValue: string | null = null;

  // Check cache
  if (enableCache) {
    globalCache.cleanup();
    decryptedValue = globalCache.get(keyId);
  }

  // Decrypt if not cached
  if (!decryptedValue) {
    try {
      // Get the appropriate provider
      const provider = providerName === 'password' ? getDefaultProvider() : getProvider(providerName);
      
      // Pass password to provider if provided and it supports password parameter
      if (password && (provider.name === 'password' || provider.name === 'tpm2')) {
        decryptedValue = await (provider as any).decrypt(encryptedValue, password);
      } else {
        decryptedValue = await provider.decrypt(encryptedValue);
      }
      
      // Cache the decrypted key
      if (enableCache && decryptedValue) {
        globalCache.set(keyId, decryptedValue, cacheTimeout);
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'DecryptionError') {
        throw error;
      }
      const keyMsg = keyName ? ` for ${keyName}` : '';
      throw new Error(`Failed to decrypt private key${keyMsg}`);
    }
  }

  if (!decryptedValue) {
    const keyMsg = keyName ? ` for ${keyName}` : '';
    throw new Error(`Failed to obtain decrypted key${keyMsg}`);
  }

  return decryptedValue;
}

/**
 * Get provider and cache settings
 */
function getProviderAndCacheSettings(
  options: { provider?: string; cache?: boolean; cacheTimeout?: string },
  config: VhsmConfig
) {
  const providerName = options.provider || config.provider || 'password';
  const provider = providerName === 'password' 
    ? getDefaultProvider() 
    : getProvider(providerName);

  const enableCache = options.cache !== false && (config.enableCache !== false);
  const cacheTimeout = options.cacheTimeout 
    ? parseInt(options.cacheTimeout, 10) 
    : (config.cacheTimeout || 3600000);

  return { provider, enableCache, cacheTimeout };
}

// ============================================================================
// Commands
// ============================================================================

async function runCommand(command: string[], options: {
  encryptedKeyFile?: string;
  provider?: string;
  password?: string;
  cache?: boolean;
  cacheTimeout?: string;
  // Pass-through options for dotenvx run
  env?: string[];
  envFile?: string[];
  envKeysFile?: string;
  envVaultFile?: string[];
  overload?: boolean;
  strict?: boolean;
  convention?: string;
  ignore?: string[];
  opsOff?: boolean;
}) {
  const config = loadConfig();
  const enableCache = options.cache !== false && (config.enableCache !== false);
  const cacheTimeout = options.cacheTimeout 
    ? parseInt(options.cacheTimeout, 10) 
    : (config.cacheTimeout || 3600000);

  // Load and parse encrypted key file
  const keyPath = options.encryptedKeyFile || '.env.keys.encrypted';
  const encryptedKeyContent = loadEncryptedKeyFile(keyPath);
  const availableKeys = parseEncryptedKeys(encryptedKeyContent);

  if (availableKeys.length === 0) {
    throw new Error('No VHSM_PRIVATE_KEY found in encrypted key file');
  }

  // Determine which keys to decrypt based on the env files passed
  const envFiles = options.envFile || ['.env'];
  const keysToProcess = matchKeysToEnvFiles(envFiles, availableKeys);

  if (keysToProcess.length === 0) {
    throw new Error('No matching encrypted keys found for the specified env files');
  }

  // Decrypt all keys (each key may use a different provider)
  const decryptedKeys: Array<{ dotenvKey: string; decryptedValue: string }> = [];

  for (const keyEntry of keysToProcess) {
    const decryptedValue = await decryptKeyWithCache(
      keyEntry.encryptedValue,
      keyEntry.provider,
      options.password,
      enableCache,
      cacheTimeout,
      keyEntry.vhsmKey
    );

    decryptedKeys.push({
      dotenvKey: keyEntry.dotenvKey,
      decryptedValue,
    });
  }

  // Prepare environment with decrypted keys
  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
  };
  
  for (const key of decryptedKeys) {
    env[key.dotenvKey] = key.decryptedValue;
  }

  // Build dotenvx run arguments
  const dotenvxArgs: string[] = ['run'];
  
  // Add pass-through options
  if (options.env && options.env.length > 0) {
    dotenvxArgs.push('-e', ...options.env);
  }
  
  if (options.envFile && options.envFile.length > 0) {
    dotenvxArgs.push('-f', ...options.envFile);
  }
  
  if (options.envKeysFile) {
    dotenvxArgs.push('-fk', options.envKeysFile);
  }
  
  if (options.envVaultFile && options.envVaultFile.length > 0) {
    dotenvxArgs.push('-fv', ...options.envVaultFile);
  }
  
  if (options.overload) {
    dotenvxArgs.push('-o');
  }
  
  if (options.strict) {
    dotenvxArgs.push('--strict');
  }
  
  if (options.convention) {
    dotenvxArgs.push('--convention', options.convention);
  }
  
  if (options.ignore && options.ignore.length > 0) {
    dotenvxArgs.push('--ignore', ...options.ignore);
  }
  
  if (options.opsOff) {
    dotenvxArgs.push('--ops-off');
  }
  
  // Add the actual command to run
  dotenvxArgs.push('--', ...command);

  // Spawn dotenvx run with the command
  const child = spawnDotenvx(dotenvxArgs, {
    stdio: 'inherit',
    env,
    shell: process.platform === 'win32',
  });

  // Clear decrypted keys from memory
  setTimeout(() => {
    for (const key of decryptedKeys) {
      clearString(key.decryptedValue);
    }
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

async function decryptCommand(options: {
  provider?: string;
  password?: string;
  cache?: boolean;
  cacheTimeout?: string;
  restore?: boolean;
  encryptedKeyFile?: string;
  envKeysFile?: string;
  envFile?: string[];
  key?: string[];
  excludeKey?: string[];
}) {
  const config = loadConfig();
  const enableCache = options.cache !== false && (config.enableCache !== false);
  const cacheTimeout = options.cacheTimeout 
    ? parseInt(options.cacheTimeout, 10) 
    : (config.cacheTimeout || 3600000);

  // Load and parse encrypted key file
  const keyPath = options.encryptedKeyFile || '.env.keys.encrypted';
  const encryptedKeyContent = loadEncryptedKeyFile(keyPath);
  const availableKeys = parseEncryptedKeys(encryptedKeyContent);

  if (availableKeys.length === 0) {
    throw new Error('No VHSM_PRIVATE_KEY found in encrypted key file');
  }

  // Match keys to env files
  const envFiles = options.envFile || ['.env'];
  const keysToProcess = matchKeysToEnvFiles(envFiles, availableKeys);

  if (keysToProcess.length === 0) {
    throw new Error('No matching encrypted keys found for the specified env files');
  }

  // Decrypt all keys (each key may use a different provider)
  const decryptedKeys: Array<{ dotenvKey: string; decryptedValue: string; envFile: string }> = [];

  for (const keyEntry of keysToProcess) {
    const decryptedValue = await decryptKeyWithCache(
      keyEntry.encryptedValue,
      keyEntry.provider,
      options.password,
      enableCache,
      cacheTimeout,
      keyEntry.vhsmKey
    );

    decryptedKeys.push({
      dotenvKey: keyEntry.dotenvKey,
      decryptedValue,
      envFile: keyEntry.envFile,
    });

    console.log(`✅ Decrypted ${keyEntry.vhsmKey} → ${keyEntry.dotenvKey} (provider: ${keyEntry.provider})`);
  }

  // If --restore is specified, write the keys to a file
  if (options.restore) {
    const outputPath = options.envKeysFile || '.env.keys';
    const { writeFileSync, readFileSync, existsSync } = await import('node:fs');
    
    let keysFileContent = '';
    const existingKeys = new Set<string>();
    
    // Check if file exists and read existing content
    if (existsSync(outputPath)) {
      const existingContent = readFileSync(outputPath, 'utf-8');
      keysFileContent = existingContent;
      
      // Extract existing key names to avoid duplicates
      const lines = existingContent.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('DOTENV_PRIVATE_KEY') && trimmed.includes('=')) {
          const keyName = trimmed.split('=')[0].trim();
          existingKeys.add(keyName);
        }
      }
      
      // Add a separator if file doesn't end with newline
      if (!keysFileContent.endsWith('\n')) {
        keysFileContent += '\n';
      }
    } else {
      // File doesn't exist - create with header
      keysFileContent = `#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/
`;
    }

    // Append new keys (skip if they already exist)
    let addedCount = 0;
    for (const key of decryptedKeys) {
      if (!existingKeys.has(key.dotenvKey)) {
        keysFileContent += `\n# ${key.envFile}\n`;
        keysFileContent += `${key.dotenvKey}=${key.decryptedValue}\n`;
        addedCount++;
      }
    }

    writeFileSync(outputPath, keysFileContent, { mode: 0o600 });
    if (addedCount > 0) {
      console.log(`✅ Restored ${addedCount} key(s) to: ${outputPath}`);
    } else {
      console.log(`✅ All keys already exist in: ${outputPath}`);
    }
  }

  // Prepare environment with decrypted keys
  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
  };
  
  for (const key of decryptedKeys) {
    env[key.dotenvKey] = key.decryptedValue;
  }

  // Build dotenvx decrypt arguments
  const dotenvxArgs: string[] = ['decrypt'];
  
  if (options.envFile && options.envFile.length > 0) {
    dotenvxArgs.push('-f', ...options.envFile);
  }
  
  if (options.envKeysFile && options.envKeysFile !== '.env.keys') {
    dotenvxArgs.push('-fk', options.envKeysFile);
  }
  
  if (options.key && options.key.length > 0) {
    dotenvxArgs.push('-k', ...options.key);
  }
  
  if (options.excludeKey && options.excludeKey.length > 0) {
    dotenvxArgs.push('-ek', ...options.excludeKey);
  }

  // Spawn dotenvx decrypt
  const child = spawnDotenvx(dotenvxArgs, {
    stdio: 'inherit',
    env,
    shell: process.platform === 'win32',
  });

  // Clear decrypted keys from memory
  setTimeout(() => {
    for (const key of decryptedKeys) {
      clearString(key.decryptedValue);
    }
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

async function encryptKey(
  keyFile: string, 
  outputPath: string, 
  providerName: string = 'password',
  providedPassword?: string, 
  shouldDelete: boolean = true,
  dotenvxOptions?: {
    envKeysFile?: string;
    envFile?: string[];
    key?: string[];
    excludeKey?: string[];
  }
) {
  const inquirer = (await import('inquirer')).default;
  
  // Validate provider
  const config = loadConfig();
  const availableProviders = listProviders();
  if (!availableProviders.includes(providerName)) {
    throw new Error(`Unknown provider: ${providerName}. Available providers: ${availableProviders.join(', ')}`);
  }
  
  // DPAPI doesn't support password parameter
  if (providerName !== 'password' && providedPassword) {
    console.warn('⚠️  Password parameter is ignored when not using password provider');
  }

  // Step 1: Check if encrypted file already exists and verify provider match BEFORE running dotenvx
  let existingEncryptedContent: string | null = null;
  let existingKeys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }> = [];
  
  if (existsSync(outputPath)) {
    existingEncryptedContent = readFileSync(outputPath, 'utf-8').trim();
    existingKeys = parseEncryptedKeys(existingEncryptedContent);
    
    if (existingKeys.length > 0) {
      // Check if any existing keys use a different provider
      const existingProviders = new Set(existingKeys.map(k => k.provider));
      const uniqueProviders = Array.from(existingProviders);
      
      // If there's a provider mismatch, show helpful error and fail early
      if (uniqueProviders.length > 0 && !uniqueProviders.includes(providerName)) {
        const currentProvider = uniqueProviders[0]; // Use first provider found
        const currentProviderDisplay = currentProvider === 'password' ? 'password (encrypted:)' : currentProvider;
        
        console.error(`\n❌ Provider mismatch detected!`);
        console.error(`   Current encrypted keys use provider: ${currentProviderDisplay}`);
        console.error(`   You requested provider: ${providerName}`);
        console.error(`\n   To change providers, you must:`);
        console.error(`   1. Decrypt the existing keys: vhsm decrypt --restore`);
        console.error(`   2. Re-encrypt with the new provider: vhsm encrypt -p ${providerName}`);
        console.error(`\n   Or use the correct provider:`);
        console.error(`   vhsm encrypt -p ${currentProvider}\n`);
        
        throw new Error(`Cannot encrypt with provider '${providerName}'. Existing encrypted keys use provider '${currentProvider}'.`);
      }
    }
  }

  // Step 2: Run dotenvx encrypt to generate/update .env.keys
  console.log('Running dotenvx encrypt...');
  
  // Build dotenvx encrypt arguments
  const dotenvxArgs: string[] = ['encrypt'];
  
  // Pass -fk flag if specified (use the one from options if provided, otherwise use keyFile parameter)
  const envKeysFile = dotenvxOptions?.envKeysFile || keyFile;
  if (envKeysFile && envKeysFile !== '.env.keys') {
    dotenvxArgs.push('-fk', envKeysFile);
  }
  
  if (dotenvxOptions?.envFile && dotenvxOptions.envFile.length > 0) {
    dotenvxArgs.push('-f', ...dotenvxOptions.envFile);
  }
  
  if (dotenvxOptions?.key && dotenvxOptions.key.length > 0) {
    dotenvxArgs.push('-k', ...dotenvxOptions.key);
  }
  
  if (dotenvxOptions?.excludeKey && dotenvxOptions.excludeKey.length > 0) {
    dotenvxArgs.push('-ek', ...dotenvxOptions.excludeKey);
  }
  
  const dotenvxEncrypt = spawnDotenvx(dotenvxArgs, {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  const encryptExitCode = await new Promise<number>((resolve) => {
    dotenvxEncrypt.on('exit', (code) => {
      resolve(code ?? 0);
    });
    
    dotenvxEncrypt.on('error', (error) => {
      console.error(`Failed to run dotenvx encrypt: ${error.message}`);
      resolve(1);
    });
  });

  if (encryptExitCode !== 0) {
    throw new Error('dotenvx encrypt failed. Please ensure dotenvx is installed and you have a .env file to encrypt.');
  }

  // Step 3: Encrypt the keys file if it exists
  if (!existsSync(keyFile)) {
    throw new Error(`Missing keys file: ${keyFile}. dotenvx encrypt should have created it.`);
  }

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
  const keyLines = lines.filter(line => line.trim().startsWith('DOTENV_PRIVATE_KEY') && line.trim().includes('='));
  
  if (keyLines.length === 0) {
    throw new Error('No DOTENV_PRIVATE_KEY found in key file');
  }

  // Extract the value after the = sign
  const keyKeys = keyLines.map(line => line.split('=')[0].trim());
  const keyValues = keyLines.map(line => line.split('=').slice(1).join('=').trim());
  
  // Convert DOTENV keys to VHSM keys to check against existing encrypted file
  const vhsmKeysToEncrypt = keyKeys.map(k => k.replace('DOTENV_', 'VHSM_'));

  // Encrypt based on provider
  // Start with existing encrypted content if it exists, otherwise create new header
  let outputContent = existingEncryptedContent 
    ? existingEncryptedContent.split('\n').filter(line => line.trim().startsWith('#')).join('\n') + '\n'
    : `#/-----------------!VHSM_PRIVATE_KEYS!------------------/
#/ VHSM encrypted keys. DO NOT commit to source control /
#/------------------------------------------------------/
`;
  
  // If we have existing keys, preserve them (unless we're re-encrypting the same key)
  if (existingKeys.length > 0) {
    const keysToReencrypt = new Set(vhsmKeysToEncrypt);
    for (const existingKey of existingKeys) {
      // Only preserve keys that we're NOT re-encrypting
      if (!keysToReencrypt.has(existingKey.vhsmKey)) {
        outputContent += `\n${existingKey.vhsmKey}=${existingKey.provider === 'password' ? 'encrypted:' : existingKey.provider + ':'}${existingKey.encryptedValue}`;
      }
    }
  }

  if (providerName === 'dpapi') {
    // DPAPI encryption - no password needed
    const { encryptKeyWithDPAPI } = await import('./providers/dpapi.js');
    
    console.log('Encrypting keys with Windows DPAPI...');
    for (const [i, key] of keyValues.entries()) {
      const encrypted = encryptKeyWithDPAPI(key);
      const encapsulatedKey = `${keyKeys[i].replace('DOTENV_', 'VHSM_')}=dpapi:${encrypted}`;
      outputContent += `\n${encapsulatedKey}`;
    }
  } else if (providerName === 'fido2') {
    // FIDO2 encryption - requires Yubikey/FIDO2 device
    const { encryptKeyWithFIDO2 } = await import('./providers/fido2.js');
    
    // Check if there are existing FIDO2 keys we can reuse the credential from
    let credentialId: string | undefined;
    const existingFido2Keys = existingKeys.filter(k => k.provider === 'fido2');
    if (existingFido2Keys.length > 0) {
      // Extract credential ID from first existing FIDO2 key (format: credId:iv:authTag:data)
      credentialId = existingFido2Keys[0].encryptedValue.split(':')[0];
      console.log('Encrypting keys with FIDO2/Yubikey...');
      console.log(`Found existing FIDO2 credential. Reusing for new keys.`);
    } else {
      console.log('Encrypting keys with FIDO2/Yubikey...');
      console.log(`Found ${keyValues.length} key(s) to encrypt.`);
      console.log('You will need to touch your Yubikey ONCE to register a credential.\n');
    }
    
    // Filter to only encrypt keys that don't already exist
    const keysToEncrypt: Array<{ index: number; key: string; vhsmKey: string }> = [];
    for (const [i, key] of keyValues.entries()) {
      const vhsmKey = keyKeys[i].replace('DOTENV_', 'VHSM_');
      if (!outputContent.includes(`${vhsmKey}=`)) {
        keysToEncrypt.push({ index: i, key, vhsmKey });
      }
    }
    
    if (keysToEncrypt.length === 0) {
      console.log('✅ All keys already encrypted. Skipping.');
    } else {
      for (const [idx, { index, key, vhsmKey }] of keysToEncrypt.entries()) {
        if (credentialId === undefined) {
          // First key and no existing credential - create new one
          console.log(`Encrypting key ${index + 1}/${keyValues.length}: ${keyKeys[index]} (creating credential)...`);
          const encrypted = await encryptKeyWithFIDO2(key);
          // Extract credential ID from first encrypted key (format: credId:iv:authTag:data)
          credentialId = encrypted.split(':')[0];
          const encapsulatedKey = `${vhsmKey}=fido2:${encrypted}`;
          outputContent += `\n${encapsulatedKey}`;
        } else {
          // Reuse existing credential
          console.log(`Encrypting key ${index + 1}/${keyValues.length}: ${keyKeys[index]} (reusing existing credential)...`);
          const encrypted = await encryptKeyWithFIDO2(key, credentialId);
          const encapsulatedKey = `${vhsmKey}=fido2:${encrypted}`;
          outputContent += `\n${encapsulatedKey}`;
        }
      }
      
      console.log(`\n✅ All ${keysToEncrypt.length} key(s) encrypted with the same FIDO2 credential.`);
    }
  } else if (providerName === 'tpm2') {
    // TPM2 encryption - optional password for additional security
    const { encryptKeyWithTPM2 } = await import('./providers/tpm2.js');
    
    let password: string | undefined;

    if (providedPassword) {
      // Use provided password
      password = providedPassword;
      if (password.length < 8) {
        throw new Error('TPM2 auth passphrase must be at least 8 characters');
      }
      console.log('Encrypting keys with TPM2 (with authorization)...');
    } else {
      // Ask if user wants to set auth password
      const authPrompt = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'useAuth',
          message: 'Set authorization password for TPM2 seal? (Recommended for extra security)',
          default: true,
        },
      ]);

      if (authPrompt.useAuth) {
        const prompts = await inquirer.prompt([
          {
            type: 'password',
            name: 'password',
            message: 'Enter TPM2 authorization password:',
            mask: '*',
            validate: (input: string) => {
              if (!input || input.length < 8) {
                return 'Password must be at least 8 characters';
              }
              return true;
            },
          },
          {
            type: 'password',
            name: 'confirmPassword',
            message: 'Confirm password:',
            mask: '*',
            validate: (input: string, answers: any) => {
              if (input !== answers.password) {
                return 'Passwords do not match';
              }
              return true;
            },
          },
        ]);
        password = prompts.password;
        console.log('Encrypting keys with TPM2 (with authorization)...');
      } else {
        console.log('Encrypting keys with TPM2 (no authorization - hardware-only)...');
      }
    }

    for (const [i, key] of keyValues.entries()) {
      const vhsmKey = keyKeys[i].replace('DOTENV_', 'VHSM_');
      // Only encrypt if this key doesn't already exist in the output
      if (!outputContent.includes(`${vhsmKey}=`)) {
        const encrypted = encryptKeyWithTPM2(key, password);
        const encapsulatedKey = `${vhsmKey}=tpm2:${encrypted}`;
        outputContent += `\n${encapsulatedKey}`;
      }
    }
  } else if (providerName === 'password') {
    // Password-based encryption
    const { encryptKeyWithPassword } = await import('./providers/password.js');
    
    let password: string;

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
    }

    for (const [i, key] of keyValues.entries()) {
      const vhsmKey = keyKeys[i].replace('DOTENV_', 'VHSM_');
      // Only encrypt if this key doesn't already exist in the output
      if (!outputContent.includes(`${vhsmKey}=`)) {
        const encrypted = encryptKeyWithPassword(key, password);
        const encapsulatedKey = `${vhsmKey}=encrypted:${encrypted}`;
        outputContent += `\n${encapsulatedKey}`;
      }
    }
  } else {
    throw new Error(`Unsupported encryption provider: ${providerName}`);
  }

  // Write to file
  const { writeFileSync, unlinkSync } = await import('node:fs');
  writeFileSync(outputPath, outputContent, { mode: 0o600 }); // Read/write for owner only

  console.log(`VHSM encrypted keys written to: ${outputPath}`);
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

