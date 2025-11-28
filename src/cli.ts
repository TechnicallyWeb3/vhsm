#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
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
  .option('-ef, --encrypted-keys-file <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
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
      await runCommand(command, options as any);
    } catch (error) {
      const sanitized = sanitizeError(error);
      console.error(`Error: ${sanitized.message}`);
      process.exit(1);
    }
  });

program
  .command('encrypt')
  .description('Encrypt a dotenvx private key')
  .option('-p, --provider <name>', 'Encryption provider to use (password, dpapi, fido2, tpm2)', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for encryption (for testing, password/tpm2 providers only)')
  .option('-nd, --no-delete', 'Do not delete the original .env.keys file after encryption')
  .option('-gi, --gitignore [patterns...]', 'Add files to .gitignore (no args = all files, or specify space-separated patterns)')
  // Pass-through options for dotenvx encrypt
  .option('-fk, --env-keys-file <path>', 'Path to plaintext private key file (output will be <path>.encrypted)', '.env.keys')
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  .option('-k, --key <keys...>', 'Key(s) to encrypt (default: all keys in file)')
  .option('-ek, --exclude-key <excludeKeys...>', 'Key(s) to exclude from encryption (default: none)')
  .action(async (options) => {
    try {
      const inputFile = options.envKeysFile || '.env.keys';
      // Derive output path from -fk: if -fk is specified, output is <fk-path>.encrypted
      // Otherwise, default to .env.keys.encrypted
      const outputPath = options.envKeysFile && options.envKeysFile !== '.env.keys'
        ? `${options.envKeysFile}.encrypted`
        : '.env.keys.encrypted';
      // --no-delete sets options.delete to false, so we delete when delete is not false
      const shouldDelete = options.delete !== false;
      await encryptKey(inputFile, outputPath, options.provider, options.password, shouldDelete, {
        envKeysFile: options.envKeysFile,
        envFile: options.envFile,
        key: options.key,
        excludeKey: options.excludeKey,
        gitignore: options.gitignore,
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
  .option('-ef, --encrypted-keys-file <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Key decryption provider to use', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for decryption (for testing)')
  .option('-nc, --no-cache', 'Disable session caching')
  .option('-ct, --cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  .option('-r, --restore', 'Restore the decrypted key to a .env.keys file')
  .option('-rm, --remove', 'Remove decrypted keys from .env.keys and .env.keys.encrypted files after decryption')
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

/**
 * Parse DOTENV_PRIVATE_KEY entries from .env.keys file
 */
function parseDotenvKeys(content: string): Array<{ dotenvKey: string; envFile: string | null }> {
  const keys: Array<{ dotenvKey: string; envFile: string | null }> = [];
  const lines = content.split('\n');
  let currentEnvFile: string | null = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track commented filename (e.g., "# .env.local")
    if (trimmed.startsWith('#') && !trimmed.startsWith('#/') && trimmed.length > 1) {
      const envFileMatch = /^#\s*(\.env[^\s]*)/.exec(trimmed);
      if (envFileMatch) {
        currentEnvFile = envFileMatch[1];
      }
      continue;
    }
    
    // Match DOTENV_PRIVATE_KEY[_SUFFIX]=...
    const match = /^(DOTENV_PRIVATE_KEY[^=]*)=(.*)/.exec(trimmed);
    if (match) {
      keys.push({
        dotenvKey: match[1],
        envFile: currentEnvFile,
      });
    }
  }
  
  return keys;
}

/**
 * Remove keys from .env.keys file
 */
function removeKeysFromDotenvKeysFile(
  filePath: string,
  keysToRemove: string[]
): { removed: boolean; shouldDelete: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false, shouldDelete: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const keysToRemoveSet = new Set(keysToRemove);
  
  const headerLines: string[] = [];
  const remainingLines: string[] = [];
  let removedAny = false;
  let pendingComment: string | null = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Keep header lines (starting with #/)
    if (trimmed.startsWith('#/')) {
      headerLines.push(line);
      pendingComment = null;
      continue;
    }
    
    // Track commented filename (e.g., "# .env.local")
    if (trimmed.startsWith('#') && !trimmed.startsWith('#/') && trimmed.length > 1) {
      const envFileMatch = /^#\s*(\.env[^\s]*)/.exec(trimmed);
      if (envFileMatch) {
        // Store this comment, but don't add it yet - wait to see if next line is a key to remove
        pendingComment = line;
        continue;
      }
    }
    
    // Check if this is a key line to remove
    const keyMatch = /^(DOTENV_PRIVATE_KEY[^=]*)=/.exec(trimmed);
    if (keyMatch && keysToRemoveSet.has(keyMatch[1])) {
      removedAny = true;
      // Skip this key and discard any pending comment
      pendingComment = null;
      continue;
    }
    
    // Keep this line - add pending comment first if it exists
    if (pendingComment !== null) {
      remainingLines.push(pendingComment);
      pendingComment = null;
    }
    remainingLines.push(line);
  }
  
  // Check if there are any keys remaining
  const remainingKeys = parseDotenvKeys(remainingLines.join('\n'));
  const shouldDelete = remainingKeys.length === 0;
  
  if (removedAny) {
    if (shouldDelete) {
      unlinkSync(filePath);
    } else {
      // Reconstruct file with header if it existed
      const newContent = headerLines.length > 0 
        ? headerLines.join('\n') + '\n' + remainingLines.join('\n')
        : remainingLines.join('\n');
      writeFileSync(filePath, newContent, { mode: 0o600 });
    }
  }
  
  return { removed: removedAny, shouldDelete };
}

/**
 * Remove keys from .env.keys.encrypted file
 */
function removeKeysFromEncryptedFile(
  filePath: string,
  vhsmKeysToRemove: string[]
): { removed: boolean; shouldDelete: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false, shouldDelete: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const keysToRemoveSet = new Set(vhsmKeysToRemove);
  
  const headerLines: string[] = [];
  const remainingLines: string[] = [];
  let removedAny = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Keep header lines (starting with #/)
    if (trimmed.startsWith('#/')) {
      headerLines.push(line);
      continue;
    }
    
    // Check if this is a key line to remove
    const keyMatch = /^(VHSM_PRIVATE_KEY[^=]*)=/.exec(trimmed);
    if (keyMatch && keysToRemoveSet.has(keyMatch[1])) {
      removedAny = true;
      continue;
    }
    
    // Keep this line
    if (trimmed) {
      remainingLines.push(line);
    }
  }
  
  // Check if there are any keys remaining
  const remainingKeys = parseEncryptedKeys(remainingLines.join('\n'));
  const shouldDelete = remainingKeys.length === 0;
  
  if (removedAny) {
    if (shouldDelete) {
      unlinkSync(filePath);
    } else {
      const newContent = headerLines.length > 0 
        ? headerLines.join('\n') + '\n' + remainingLines.join('\n')
        : remainingLines.join('\n');
      writeFileSync(filePath, newContent, { mode: 0o600 });
    }
  }
  
  return { removed: removedAny, shouldDelete };
}

/**
 * Check if a pattern exists in .gitignore
 */
function isPatternInGitignore(pattern: string, gitignorePath: string = '.gitignore'): boolean {
  if (!existsSync(gitignorePath)) {
    return false;
  }
  
  const content = readFileSync(gitignorePath, 'utf-8');
  const lines = content.split('\n');
  
  // Normalize pattern for comparison (remove leading/trailing whitespace)
  const normalizedPattern = pattern.trim();
  
  for (const line of lines) {
    const trimmed = line.trim();
    // Check for exact match or if the line contains the pattern
    // Also handle patterns with wildcards or path separators
    if (trimmed === normalizedPattern || 
        trimmed === `/${normalizedPattern}` ||
        trimmed.endsWith(normalizedPattern) ||
        trimmed.includes(normalizedPattern)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Add a pattern to .gitignore
 */
function addPatternToGitignore(pattern: string, gitignorePath: string = '.gitignore'): void {
  let content = '';
  
  if (existsSync(gitignorePath)) {
    content = readFileSync(gitignorePath, 'utf-8');
    // Ensure file ends with newline
    if (!content.endsWith('\n')) {
      content += '\n';
    }
  }
  
  // Add the pattern
  content += `${pattern}\n`;
  
  writeFileSync(gitignorePath, content, { mode: 0o644 });
}

/**
 * Remove header, public key, and filename comment from .env file
 * Removes everything from the first #/ line up to and including the first # .env* comment
 */
function removeHeaderAndPublicKeyFromEnvFile(filePath: string): { removed: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const remainingLines: string[] = [];
  let removedAny = false;
  let inHeaderSection = true;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    if (inHeaderSection) {
      // Skip header lines (starting with #/)
      if (trimmed.startsWith('#/')) {
        removedAny = true;
        continue;
      }
      
      // Skip public key line (DOTENV_PUBLIC_KEY or DOTENV_PUBLIC_KEY_*)
      if (/^DOTENV_PUBLIC_KEY[^=]*=/.test(trimmed)) {
        removedAny = true;
        continue;
      }
      
      // Skip empty lines in the header section
      if (!trimmed) {
        removedAny = true;
        continue;
      }
      
      // Skip filename comment (e.g., "# .env.local" or "# .env")
      // This marks the end of the header section
      if (trimmed.startsWith('#') && /^#\s*\.env/.test(trimmed)) {
        removedAny = true;
        inHeaderSection = false; // End of header section, start keeping lines
        continue;
      }
    }
    
    // Keep all lines after the header section
    remainingLines.push(line);
  }
  
  if (removedAny) {
    // Write back the cleaned content, preserving trailing newlines
    const newContent = remainingLines.join('\n');
    writeFileSync(filePath, newContent, { mode: 0o644 });
  }
  
  return { removed: removedAny };
}

// ============================================================================
// Commands
// ============================================================================

async function runCommand(command: string[], options: {
  encryptedKeysFile?: string;
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
  const keyPath = options.encryptedKeysFile || '.env.keys.encrypted';
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
  remove?: boolean;
  encryptedKeysFile?: string;
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

  // Validate conflicting options
  if (options.restore && options.remove) {
    throw new Error('Cannot use --restore and --remove together. --restore writes keys to a file, while --remove deletes them. Please use only one option.');
  }

  // Handle remove option with -k or -ek flags
  let finalOptions = { ...options };
  if (options.remove && (options.key || options.excludeKey)) {
    const inquirer = (await import('inquirer')).default;
    console.warn('\n⚠️  WARNING: Using --remove with -k/--key or -ek/--exclude-key flags will cause loss of secrets!');
    console.warn('   Only the specified keys will be removed, potentially leaving other keys encrypted.');
    
    const answer = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: 'Proceed with removing only the specified keys? (y/n)',
        default: false,
      },
    ]);
    
    if (!answer.proceed) {
      console.log('Removing -k/--key and -ek/--exclude-key flags. All keys will be decrypted and removed.');
      finalOptions = { ...options, key: undefined, excludeKey: undefined };
    }
  }

  // Load and parse encrypted key file
  const keyPath = finalOptions.encryptedKeysFile || '.env.keys.encrypted';
  const encryptedKeyContent = loadEncryptedKeyFile(keyPath);
  const availableKeys = parseEncryptedKeys(encryptedKeyContent);

  if (availableKeys.length === 0) {
    throw new Error('No VHSM_PRIVATE_KEY found in encrypted key file');
  }

  // Match keys to env files
  const envFiles = finalOptions.envFile || ['.env'];
  const keysToProcess = matchKeysToEnvFiles(envFiles, availableKeys);

  if (keysToProcess.length === 0) {
    throw new Error('No matching encrypted keys found for the specified env files');
  }

  // Check if any keys use password provider and prompt once if needed
  let passwordForDecrypt = finalOptions.password;
  const passwordKeys = keysToProcess.filter(k => k.provider === 'password');
  
  if (passwordKeys.length > 0 && !passwordForDecrypt) {
    const inquirer = (await import('inquirer')).default;
    const passwordPrompt = await inquirer.prompt([
      {
        type: 'password',
        name: 'password',
        message: 'Enter passphrase to decrypt keys:',
        mask: '*',
        validate: (input: string) => {
          if (!input || input.length === 0) {
            return 'Passphrase cannot be empty';
          }
          return true;
        },
      },
    ]);
    passwordForDecrypt = passwordPrompt.password;
  }

  // Decrypt all keys (each key may use a different provider)
  const decryptedKeys: Array<{ dotenvKey: string; decryptedValue: string; envFile: string; vhsmKey: string }> = [];

  for (const keyEntry of keysToProcess) {
    // Use the password we prompted for if this is a password key
    const passwordToUse = keyEntry.provider === 'password' ? passwordForDecrypt : finalOptions.password;
    
    const decryptedValue = await decryptKeyWithCache(
      keyEntry.encryptedValue,
      keyEntry.provider,
      passwordToUse,
      enableCache,
      cacheTimeout,
      keyEntry.vhsmKey
    );

    decryptedKeys.push({
      dotenvKey: keyEntry.dotenvKey,
      decryptedValue,
      envFile: keyEntry.envFile,
      vhsmKey: keyEntry.vhsmKey,
    });

    console.log(`✅ Decrypted ${keyEntry.vhsmKey} → ${keyEntry.dotenvKey} (provider: ${keyEntry.provider})`);
  }

  // If --restore is specified, write the keys to a file
  if (finalOptions.restore) {
    const outputPath = finalOptions.envKeysFile || '.env.keys';
    
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
  
  if (finalOptions.envFile && finalOptions.envFile.length > 0) {
    dotenvxArgs.push('-f', ...finalOptions.envFile);
  }
  
  if (finalOptions.envKeysFile && finalOptions.envKeysFile !== '.env.keys') {
    dotenvxArgs.push('-fk', finalOptions.envKeysFile);
  }
  
  if (finalOptions.key && finalOptions.key.length > 0) {
    dotenvxArgs.push('-k', ...finalOptions.key);
  }
  
  if (finalOptions.excludeKey && finalOptions.excludeKey.length > 0) {
    dotenvxArgs.push('-ek', ...finalOptions.excludeKey);
  }

  // Spawn dotenvx decrypt
  const child = spawnDotenvx(dotenvxArgs, {
    stdio: 'inherit',
    env,
    shell: process.platform === 'win32',
  });

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

  // If --remove is specified, remove keys from files after successful decryption
  if (finalOptions.remove && exitCode === 0) {
    const dotenvKeysToRemove = decryptedKeys.map(k => k.dotenvKey);
    const vhsmKeysToRemove = decryptedKeys.map(k => k.vhsmKey);
    
    const keysFilePath = finalOptions.envKeysFile || '.env.keys';
    const encryptedFilePath = finalOptions.encryptedKeysFile || '.env.keys.encrypted';
    
    // Remove from .env.keys file
    const keysResult = removeKeysFromDotenvKeysFile(keysFilePath, dotenvKeysToRemove);
    if (keysResult.removed) {
      if (keysResult.shouldDelete) {
        console.log(`✅ Removed keys and deleted ${keysFilePath} (no keys remaining)`);
      } else {
        console.log(`✅ Removed keys from ${keysFilePath}`);
      }
    }
    
    // Remove from .env.keys.encrypted file
    const encryptedResult = removeKeysFromEncryptedFile(encryptedFilePath, vhsmKeysToRemove);
    if (encryptedResult.removed) {
      if (encryptedResult.shouldDelete) {
        console.log(`✅ Removed keys and deleted ${encryptedFilePath} (no keys remaining)`);
      } else {
        console.log(`✅ Removed keys from ${encryptedFilePath}`);
      }
    }
    
    // Remove header, public key, and filename comment from .env files
    const envFiles = finalOptions.envFile || ['.env'];
    for (const envFile of envFiles) {
      const envResult = removeHeaderAndPublicKeyFromEnvFile(envFile);
      if (envResult.removed) {
        console.log(`✅ Removed header, public key, and filename comment from ${envFile}`);
      }
    }
  }

  // Clear decrypted keys from memory
  setTimeout(() => {
    for (const key of decryptedKeys) {
      clearString(key.decryptedValue);
    }
  }, 100);

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
    gitignore?: string[] | boolean;
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

  // Step 2: Validate encryption will succeed BEFORE running dotenvx encrypt
  // This ensures we don't create .env.keys if encryption will fail
  let validatedCredentialId: string | undefined;
  let validatedPassword: string | undefined;
  
  if (providerName === 'fido2') {
    // For FIDO2, validate credential creation/reuse BEFORE dotenvx
    const { encryptKeyWithFIDO2 } = await import('./providers/fido2.js');
    
    const existingFido2Keys = existingKeys.filter(k => k.provider === 'fido2');
    if (existingFido2Keys.length > 0) {
      // Extract credential ID from existing key
      validatedCredentialId = existingFido2Keys[0].encryptedValue.split(':')[0];
      console.log('Validating FIDO2 credential...');
      // Test encrypt with dummy data to ensure credential is usable
      try {
        await encryptKeyWithFIDO2('test-validation', validatedCredentialId);
        console.log('✅ FIDO2 credential validated.');
      } catch (error) {
        throw new Error(`FIDO2 credential validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    } else {
      // Need to create new credential - do it NOW before dotenvx
      console.log('Creating FIDO2 credential (this will open a browser window)...');
      console.log('You will need to touch your Yubikey ONCE to register a credential.\n');
      try {
        // Create credential with test data
        const testEncrypted = await encryptKeyWithFIDO2('test-validation');
        validatedCredentialId = testEncrypted.split(':')[0];
        console.log('✅ FIDO2 credential created and validated.');
      } catch (error) {
        throw new Error(`FIDO2 credential creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  } else if (providerName === 'password') {
    // For password, prompt and validate BEFORE dotenvx
    const { encryptKeyWithPassword, PasswordProvider } = await import('./providers/password.js');
    const passwordProvider = new PasswordProvider();
    
    if (providedPassword) {
      validatedPassword = providedPassword;
      if (validatedPassword.length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
      }
    } else {
      // Check if there are existing password-encrypted keys
      const existingPasswordKeys = existingKeys.filter(k => k.provider === 'password');
      
      if (existingPasswordKeys.length > 0) {
        // Validate password against existing key
        console.log('Existing encrypted keys found. Please enter the same passphrase to add a new key.');
        let passwordValid = false;
        let attempts = 0;
        const maxAttempts = 3;
        
        while (!passwordValid && attempts < maxAttempts) {
          const passwordPrompt = await inquirer.prompt([
            {
              type: 'password',
              name: 'password',
              message: 'Enter passphrase to validate (must match existing keys):',
              mask: '*',
              validate: (input: string) => {
                if (!input || input.length === 0) {
                  return 'Passphrase cannot be empty';
                }
                return true;
              },
            },
          ]);
          
          // Try to decrypt an existing key to validate the password
          try {
            await passwordProvider.decrypt(existingPasswordKeys[0].encryptedValue, passwordPrompt.password);
            validatedPassword = passwordPrompt.password;
            passwordValid = true;
            console.log('✅ Password validated against existing keys.');
          } catch (error) {
            attempts++;
            if (attempts < maxAttempts) {
              console.error(`❌ Password does not match existing keys. ${maxAttempts - attempts} attempt(s) remaining.`);
            } else {
              throw new Error('Password validation failed. Maximum attempts reached.');
            }
          }
        }
      } else {
        // No existing keys, prompt for new password with confirmation
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
        validatedPassword = prompts.password;
      }
    }
    
    // Test encrypt with dummy data to validate password works
    try {
      await encryptKeyWithPassword('test-validation', validatedPassword!);
      if (existingKeys.length === 0) {
        console.log('✅ Password validated.');
      }
    } catch (error) {
      throw new Error(`Password validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  } else if (providerName === 'tpm2') {
    // For TPM2, prompt for password if needed BEFORE dotenvx
    if (providedPassword) {
      validatedPassword = providedPassword;
      if (validatedPassword.length < 8) {
        throw new Error('TPM2 auth passphrase must be at least 8 characters');
      }
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
        validatedPassword = prompts.password;
      }
    }
    
    // Test encrypt with dummy data to validate TPM2 works
    const { encryptKeyWithTPM2 } = await import('./providers/tpm2.js');
    try {
      encryptKeyWithTPM2('test-validation', validatedPassword);
      console.log('✅ TPM2 validated.');
    } catch (error) {
      throw new Error(`TPM2 validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  } else if (providerName === 'dpapi') {
    // DPAPI doesn't need validation - it always works on Windows
    // (Already checked platform in provider check)
    console.log('✅ DPAPI ready.');
  }

  // Step 2.5: Check and optionally add files to .gitignore
  const gitignorePath = '.gitignore';
  const envKeysFile = dotenvxOptions?.envKeysFile || keyFile;
  
  // Helper function to check if pattern exists in .gitignore
  const checkGitignorePattern = (pattern: string): boolean => {
    const patternsToCheck = [
      pattern,
      `/${pattern}`,
      `**/${pattern}`,
    ];
    
    for (const checkPattern of patternsToCheck) {
      if (isPatternInGitignore(checkPattern, gitignorePath)) {
        return true;
      }
    }
    return false;
  };

  // Collect all files that should be in .gitignore
  const filesToCheck: Array<{ name: string; displayName: string; type: string }> = [];
  
  // Add .env files
  const envFiles = dotenvxOptions?.envFile || ['.env'];
  for (const envFile of envFiles) {
    const envFileName = envFile.includes('/') || envFile.includes('\\') 
      ? envFile.split(/[/\\]/).pop() || envFile
      : envFile;
    filesToCheck.push({
      name: envFileName,
      displayName: envFileName,
      type: 'environment variables',
    });
  }

  // Add .env.keys file (only if -fk flag is used)
  if (dotenvxOptions?.envKeysFile) {
    const keysFileName = envKeysFile.includes('/') || envKeysFile.includes('\\') 
      ? envKeysFile.split(/[/\\]/).pop() || envKeysFile
      : envKeysFile;
    filesToCheck.push({
      name: keysFileName,
      displayName: keysFileName,
      type: 'private keys',
    });
  }

  // Add .env.keys.encrypted file
  const encryptedFileName = outputPath.includes('/') || outputPath.includes('\\') 
    ? outputPath.split(/[/\\]/).pop() || outputPath
    : outputPath;
  filesToCheck.push({
    name: encryptedFileName,
    displayName: encryptedFileName,
    type: 'encrypted keys',
  });

  // Check which files are missing from .gitignore
  const missingFiles = filesToCheck.filter(file => !checkGitignorePattern(file.name));

  // Handle -gi flag
  if (dotenvxOptions?.gitignore !== undefined && dotenvxOptions.gitignore !== false) {
    const gitignoreFlag = dotenvxOptions.gitignore;
    
    // Check if it's an array with values or just a boolean/empty array
    if (Array.isArray(gitignoreFlag)) {
      if (gitignoreFlag.length === 0) {
        // No args: add all missing files
        for (const file of missingFiles) {
          addPatternToGitignore(file.name, gitignorePath);
          console.log(`✅ Added ${file.displayName} to .gitignore`);
        }
      } else {
        // With args: add only specified patterns
        for (const pattern of gitignoreFlag) {
          if (!checkGitignorePattern(pattern)) {
            addPatternToGitignore(pattern, gitignorePath);
            console.log(`✅ Added ${pattern} to .gitignore`);
          }
        }
      }
    } else if (gitignoreFlag === true) {
      // Boolean true: add all missing files
      for (const file of missingFiles) {
        addPatternToGitignore(file.name, gitignorePath);
        console.log(`✅ Added ${file.displayName} to .gitignore`);
      }
    }
  } else {
    // No -gi flag: show warnings for missing files
    for (const file of missingFiles) {
      console.warn(`⚠️  ${file.displayName} is not in .gitignore (recommended to prevent committing ${file.type})`);
      console.warn(`   Add it manually or use: vhsm encrypt -gi ${file.name}`);
    }
  }

  // Step 3: Run dotenvx encrypt to generate/update .env.keys (only after validation)
  // Build dotenvx encrypt arguments
  const dotenvxArgs: string[] = ['encrypt', '-q']; // -q for quiet mode to hide private key
  
  // Pass -fk flag if specified (use the one from options if provided, otherwise use keyFile parameter)
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
    stdio: 'pipe', // Use pipe instead of inherit to suppress output
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

  // Show success message with files that were encrypted
  const encryptedEnvFiles = dotenvxOptions?.envFile || ['.env'];
  const filesList = encryptedEnvFiles.join(',');
  console.log(`✅ encrypted (${filesList})`);

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
    // FIDO2 encryption - credential already validated and created if needed
    const { encryptKeyWithFIDO2 } = await import('./providers/fido2.js');
    
    console.log('Encrypting keys with FIDO2/Yubikey...');
    if (validatedCredentialId) {
      console.log(`Using validated FIDO2 credential.`);
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
        console.log(`Encrypting key ${index + 1}/${keyValues.length}: ${keyKeys[index]}...`);
        // Use the validated credential ID (already created/validated before dotenvx)
        const encrypted = await encryptKeyWithFIDO2(key, validatedCredentialId);
        const encapsulatedKey = `${vhsmKey}=fido2:${encrypted}`;
        outputContent += `\n${encapsulatedKey}`;
      }
      
      console.log(`\n✅ All ${keysToEncrypt.length} key(s) encrypted with the same FIDO2 credential.`);
    }
  } else if (providerName === 'tpm2') {
    // TPM2 encryption - password already validated before dotenvx
    const { encryptKeyWithTPM2 } = await import('./providers/tpm2.js');
    
    console.log('Encrypting keys with TPM2...');
    if (validatedPassword) {
      console.log('Using validated TPM2 authorization.');
    } else {
      console.log('Using TPM2 hardware-only (no authorization).');
    }

    for (const [i, key] of keyValues.entries()) {
      const vhsmKey = keyKeys[i].replace('DOTENV_', 'VHSM_');
      // Only encrypt if this key doesn't already exist in the output
      if (!outputContent.includes(`${vhsmKey}=`)) {
        const encrypted = encryptKeyWithTPM2(key, validatedPassword);
        const encapsulatedKey = `${vhsmKey}=tpm2:${encrypted}`;
        outputContent += `\n${encapsulatedKey}`;
      }
    }
  } else if (providerName === 'password') {
    // Password-based encryption - password already validated before dotenvx
    const { encryptKeyWithPassword } = await import('./providers/password.js');
    
    console.log('Encrypting keys with password (using Argon2id)...');

    for (const [i, key] of keyValues.entries()) {
      const vhsmKey = keyKeys[i].replace('DOTENV_', 'VHSM_');
      // Only encrypt if this key doesn't already exist in the output
      if (!outputContent.includes(`${vhsmKey}=`)) {
        const encrypted = await encryptKeyWithPassword(key, validatedPassword!);
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

