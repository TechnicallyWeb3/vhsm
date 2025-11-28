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

export async function setCommand(options: {
  encryptedKeysFile?: string;
  provider?: string;
  password?: string;
  cache?: boolean;
  cacheTimeout?: string;
  // Pass-through options for dotenvx set
  key?: string;
  value?: string;
  envFile?: string[];
  envKeysFile?: string;
  plain?: boolean;
}) {
  const config = loadConfig();
  const enableCache = options.cache !== false && (config.enableCache !== false);
  const cacheTimeout = options.cacheTimeout 
    ? parseInt(options.cacheTimeout, 10) 
    : (config.cacheTimeout || 3600000);

  // Validate required arguments
  if (!options.key) {
    throw new Error('KEY argument is required');
  }
  if (!options.value) {
    throw new Error('value argument is required');
  }

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

  // Validate that the specified provider matches the provider used to encrypt the keys
  const specifiedProvider = options.provider || 'password';
  for (const keyEntry of keysToProcess) {
    if (keyEntry.provider !== specifiedProvider) {
      throw new Error(
        `Provider mismatch: Key ${keyEntry.vhsmKey} was encrypted with provider "${keyEntry.provider}", ` +
        `but you specified provider "${specifiedProvider}". Use the same provider that was used to encrypt the key.`
      );
    }
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

  // Build dotenvx set arguments
  const dotenvxArgs: string[] = ['set', options.key, options.value];
  
  // Add pass-through options
  if (options.envFile && options.envFile.length > 0) {
    dotenvxArgs.push('-f', ...options.envFile);
  }
  
  if (options.envKeysFile) {
    dotenvxArgs.push('-fk', options.envKeysFile);
  }
  
  // dotenvx set defaults to encrypt=true, so we only need to handle --plain
  if (options.plain) {
    dotenvxArgs.push('--plain');
  }

  // Spawn dotenvx set
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

