import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { getProvider, getDefaultProvider } from '../../providers/index.js';
import { SessionCache } from '../../cache.js';
import { createKeyId, clearString } from '../../security.js';
import { loadConfig } from '../../config.js';
import { 
  loadEncryptedKeyFile, 
  parseEncryptedKeys, 
  matchKeysToEnvFiles,
  spawnDotenvx,
  removeKeysFromDotenvKeysFile,
  removeKeysFromEncryptedFile,
  removeHeaderAndPublicKeyFromEnvFile
} from '../utils.js';

// Global session cache instance
const globalCache = new SessionCache();

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
      
      // Build config with password if provided
      const config = password ? { password } : undefined;
      decryptedValue = await provider.decrypt(encryptedValue, config);
      
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

export async function decryptCommand(options: {
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
  keyOnly?: boolean;
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

  // Validate key-only flag conflicts
  if (options.keyOnly && (options.key || options.excludeKey)) {
    throw new Error('Cannot use --key-only with -k/--key or -ek/--exclude-key. --key-only only decrypts private keys and does not decrypt env vars.');
  }

  // Handle remove option with -k or -ek flags
  let finalOptions = { ...options };
  
  // Handle remove option with key-only flag (without restore)
  if (options.remove && options.keyOnly && !options.restore) {
    const inquirer = (await import('inquirer')).default;
    console.warn('\n⚠️  WARNING: Using --remove with --key-only without --restore will cause loss of your decrypted keys!');
    console.warn('   The keys will be output to stdout but then removed from files.');
    
    const answer = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: 'Proceed without saving keys to file? (y/n)',
        default: false,
      },
    ]);
    
    if (!answer.proceed) {
      console.log('Removing --remove flag and adding --restore to save keys to file.');
      finalOptions = { ...options, restore: true, remove: false };
    }
  }
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
    
    // Build config with password if available
    const config = passwordToUse ? { password: passwordToUse } : undefined;
    
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

  // If --key-only is set, skip dotenvx decrypt and exit early
  if (finalOptions.keyOnly) {
    // If --restore is not set, output keys to stdout
    if (!finalOptions.restore) {
      for (const key of decryptedKeys) {
        process.stdout.write(`${key.dotenvKey}=${key.decryptedValue}\n`);
      }
      console.error('\n💡 Tip: Use --restore to save keys to a file instead of stdout');
    } else {
      console.log('✅ Decrypted private keys only (env vars not decrypted)');
    }
    
    // If --remove is specified, remove keys from files
    if (finalOptions.remove) {
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
          console.log(`✅ Removed keys, headers, and deleted ${encryptedFilePath} (no keys remaining)`);
        } else {
          console.log(`✅ Removed keys and env headers from ${encryptedFilePath}`);
        }
      }
      
      // Remove header, public key, and filename comment from .env files
      const envFiles = finalOptions.envFile || ['.env'];
      for (const envFile of envFiles) {
        const envResult = removeHeaderAndPublicKeyFromEnvFile(envFile);
        if (envResult.removed) {
          // console.log(`✅ Removed header, public key, and filename comment from ${envFile}`);
        }
      }
    }
    
    // Clear decrypted keys from memory
    setTimeout(() => {
      for (const key of decryptedKeys) {
        clearString(key.decryptedValue);
      }
    }, 100);
    
    process.exit(0);
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

