#!/usr/bin/env node

import { createRequire } from 'node:module';
import { Command } from 'commander';
import { sanitizeError } from '../security.js';
import { SessionCache } from '../cache.js';
import { runCommand } from './actions/run.js';
import { decryptCommand } from './actions/decrypt.js';
import { encryptKey } from './actions/encrypt.js';
import { getCommand } from './actions/get.js';
import { setCommand } from './actions/set.js';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { name?: string; version?: string; description?: string };

const program = new Command();

// Global session cache instance
const globalCache = new SessionCache();

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
  .option('-ko, --key-only', 'Only decrypt the dotenvx private keys, do not decrypt env vars')
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
  .command('get')
  .description('Decrypt dotenvx private key and get environment variable(s)')
  .argument('[KEY]', 'Environment variable name')
  .option('-ef, --encrypted-keys-file <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-pw, --password <pass>', 'Password/passphrase for decryption (for testing, password/tpm2 providers only)')
  .option('-nc, --no-cache', 'Disable session caching')
  .option('-ct, --cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  // Pass-through options for dotenvx get
  .option('-e, --env <strings...>', 'Environment variable(s) set as string (example: "HELLO=World")')
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  .option('-fk, --env-keys-file <path>', 'Path to your .env.keys file')
  .option('-fv, --env-vault-file <paths...>', 'Path(s) to your .env.vault file(s)')
  .option('-o, --overload', 'Override existing env variables')
  .option('--strict', 'Process.exit(1) on any errors')
  .option('--convention <name>', 'Load a .env convention (available: nextjs, flow)')
  .option('--ignore <errorCodes...>', 'Error code(s) to ignore (example: MISSING_ENV_FILE)')
  .option('-a, --all', 'Include all machine envs as well')
  .option('-pp, --pretty-print', 'Pretty print output')
  .option('--format <type>', 'Format of the output (json, shell, eval)', 'json')
  .action(async (key: string | undefined, options) => {
    try {
      await getCommand({ ...options, key });
    } catch (error) {
      const sanitized = sanitizeError(error);
      console.error(`Error: ${sanitized.message}`);
      process.exit(1);
    }
  });

program
  .command('set')
  .description('Decrypt dotenvx private key and set environment variable')
  .argument('<KEY>', 'Environment variable name')
  .argument('<value>', 'Value to set')
  .option('-ef, --encrypted-keys-file <path>', 'Path to encrypted private key file', '.env.keys.encrypted')
  .option('-p, --provider <name>', 'Key decryption provider to use', 'password')
  .option('-pw, --password <pass>', 'Password/passphrase for decryption (for testing)')
  .option('-nc, --no-cache', 'Disable session caching')
  .option('-ct, --cache-timeout <ms>', 'Cache timeout in milliseconds', '3600000')
  // Pass-through options for dotenvx set
  .option('-f, --env-file <paths...>', 'Path(s) to your env file(s)')
  .option('-fk, --env-keys-file <path>', 'Path to your .env.keys file')
  .option('--plain', 'Store value as plain text (default: false)')
  .action(async (key: string, value: string, options) => {
    try {
      await setCommand({ ...options, key, value });
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

// Parse CLI arguments
program.parse();

