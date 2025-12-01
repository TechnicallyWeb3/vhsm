import { getProvider, getDefaultProvider } from '../../providers/index.js';
import { SessionCache } from '../../cache.js';
import { createKeyId, clearString } from '../../security.js';
import { loadConfig } from '../../config.js';
import { 
  loadEncryptedKeyFile, 
  parseEncryptedKeys, 
  matchKeysToEnvFiles,
  spawnDotenvx 
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

export async function runCommand(command: string[], options: {
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

  const decryptedKeys: Array<{ dotenvKey: string; decryptedValue: string }> = [];

  try {
    // Load and parse encrypted key file
    const keyPath = options.encryptedKeysFile || '.env.keys.encrypted';
    const encryptedKeyContent = loadEncryptedKeyFile(keyPath);
    const availableKeys = parseEncryptedKeys(encryptedKeyContent);

    if (availableKeys.length === 0) {
      console.warn('⚠️  No VHSM_PRIVATE_KEY found in encrypted key file. Continuing without VHSM keys.');
    } else {
      // Determine which keys to decrypt based on the env files passed
      const envFiles = options.envFile || ['.env'];
      const keysToProcess = matchKeysToEnvFiles(envFiles, availableKeys);

      if (keysToProcess.length === 0) {
        console.warn('⚠️  No matching encrypted keys found for the specified env files. Continuing without VHSM keys.');
      } else {
        // Decrypt all keys (each key may use a different provider)
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
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`⚠️  Failed to prepare VHSM keys (${message}). Continuing without VHSM keys.`);
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

