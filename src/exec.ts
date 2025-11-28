/**
 * Virtual HSM - Secure function execution with environment variable support
 * 
 * Executes functions with automatic decryption and injection of environment variables
 * marked with the "@vhsm " prefix.
 */

import { getProvider, getDefaultProvider } from './providers/index.js';
import { SessionCache } from './cache.js';
import { createKeyId, clearString } from './security.js';
import { loadConfig } from './config.js';
import { 
  loadEncryptedKeyFile, 
  parseEncryptedKeys, 
  matchKeysToEnvFiles 
} from './cli/utils.js';
import { config as dotenvxConfig, get as dotenvxGet } from '@dotenvx/dotenvx';
import { readFileSync, existsSync } from 'node:fs';

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

/**
 * Get decrypted dotenvx private key and prepare environment
 */
async function getDecryptedKey(
  encryptedKeysFile: string = '.env.keys.encrypted',
  envFile: string = '.env',
  provider?: string,
  password?: string,
  enableCache?: boolean,
  cacheTimeout?: number
): Promise<string> {
  const config = loadConfig();
  const useCache = enableCache !== false && (config.enableCache !== false);
  const timeout = cacheTimeout || config.cacheTimeout || 3600000;

  // Load and parse encrypted key file
  const encryptedKeyContent = loadEncryptedKeyFile(encryptedKeysFile);
  const availableKeys = parseEncryptedKeys(encryptedKeyContent);

  if (availableKeys.length === 0) {
    throw new Error('No VHSM_PRIVATE_KEY found in encrypted key file');
  }

  // Match key to env file
  const envFiles = [envFile];
  const keysToProcess = matchKeysToEnvFiles(envFiles, availableKeys);

  if (keysToProcess.length === 0) {
    throw new Error(`No matching encrypted keys found for ${envFile}`);
  }

  // Get the key entry
  const keyEntry = keysToProcess[0];
  
  // Decrypt the key
  const providerName = provider || keyEntry.provider;
  const decryptedKey = await decryptKeyWithCache(
    keyEntry.encryptedValue,
    providerName,
    password,
    useCache,
    timeout,
    keyEntry.vhsmKey
  );

  return decryptedKey;
}

/**
 * Options for vhsm.exec()
 */
export interface ExecOptions {
  /**
   * Path to encrypted private key file
   * @default '.env.keys.encrypted'
   */
  encryptedKeysFile?: string;
  
  /**
   * Path to .env file
   * @default '.env'
   */
  envFile?: string;
  
  /**
   * Provider name to use for decryption
   * If not provided, will use the provider specified in the encrypted key file
   */
  provider?: string;
  
  /**
   * Password/passphrase for decryption (for password provider)
   */
  password?: string;
  
  /**
   * Whether to enable session caching
   * @default true
   */
  enableCache?: boolean;
  
  /**
   * Cache timeout in milliseconds
   * @default 3600000 (1 hour)
   */
  cacheTimeout?: number;
  
  /**
   * Custom path to .env.keys file (for dotenvx)
   */
  envKeysFile?: string;
}

/**
 * Process parameters object, replacing "@vhsm KEY" strings with actual env variable values
 */
async function processParams(
  params: Record<string, unknown>,
  options: ExecOptions
): Promise<Record<string, unknown>> {
  const processed: Record<string, unknown> = {};
  const sensitiveValues: string[] = [];
  
  // Get decrypted key once for all env variable retrievals
  const decryptedKey = await getDecryptedKey(
    options.encryptedKeysFile,
    options.envFile,
    options.provider,
    options.password,
    options.enableCache,
    options.cacheTimeout
  );

  // Set up environment for dotenvx
  const originalEnv: Record<string, string | undefined> = {};
  
  // Determine which DOTENV_PRIVATE_KEY to use based on env file
  const envSuffix = options.envFile && options.envFile !== '.env'
    ? options.envFile.replace(/^\.env\./, '_').toUpperCase().replace(/[^A-Z0-9_]/g, '')
    : '';
  
  const dotenvKeyName = `DOTENV_PRIVATE_KEY${envSuffix}`;
  
  try {
    // Store original value if it exists
    if (process.env[dotenvKeyName] !== undefined) {
      originalEnv[dotenvKeyName] = process.env[dotenvKeyName];
    }
    
    // Set the decrypted key in environment
    process.env[dotenvKeyName] = decryptedKey;

    // Create a custom processEnv object to load decrypted env variables
    const processEnv: Record<string, string> = {};
    
    // Load all env variables from the .env file using dotenvx
    const envFile = options.envFile || '.env';
    const configOptions = {
      path: envFile,
      processEnv: processEnv,
      envKeysFile: options.envKeysFile,
      strict: false,
      quiet: true,
    };
    
    const configResult = dotenvxConfig(configOptions);
    if (configResult.error && !configResult.error.message.includes('MISSING_ENV_FILE')) {
      throw configResult.error;
    }

    // Process each parameter
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && value.startsWith('@vhsm ')) {
        // Extract the env variable name
        const envKey = value.slice(6).trim(); // Remove '@vhsm ' prefix
        
        // Get the env variable from the loaded processEnv
        const envValue = processEnv[envKey];
        
        if (envValue === undefined) {
          throw new Error(`Environment variable '${envKey}' not found in ${envFile}`);
        }
        
        processed[key] = envValue;
        // Track sensitive values for cleanup
        if (typeof envValue === 'string') {
          sensitiveValues.push(envValue);
        }
      } else {
        processed[key] = value;
      }
    }
    
    // Clear all loaded env variables from processEnv
    for (const key of Object.keys(processEnv)) {
      const value = processEnv[key];
      if (typeof value === 'string') {
        clearString(value);
      }
      delete processEnv[key];
    }
  } finally {
    // Restore original DOTENV_PRIVATE_KEY if it existed
    if (originalEnv[dotenvKeyName] !== undefined) {
      process.env[dotenvKeyName] = originalEnv[dotenvKeyName];
    } else {
      delete process.env[dotenvKeyName];
    }
    // Clear decrypted key from memory
    clearString(decryptedKey);
  }

  // Store sensitive values for cleanup after execution
  (processed as any).__sensitiveValues = sensitiveValues;
  
  return processed;
}

/**
 * Execute a function with automatic environment variable decryption and injection
 * 
 * @example
 * ```typescript
 * const result = await vhsm.exec(
 *   async ({ message, nonce, apiKey }) => {
 *     // Use apiKey which was automatically decrypted from @vhsm API_KEY
 *     return signMessage(message, nonce, apiKey);
 *   },
 *   {
 *     message: 'Hello, World!',
 *     nonce: '123456',
 *     apiKey: '@vhsm API_KEY'
 *   }
 * );
 * ```
 * 
 * @param fn - The function to execute
 * @param params - Parameters to pass to the function. Use "@vhsm KEY" to inject env variables
 * @param options - Execution options
 * @returns The result of executing the function
 */
export async function exec<T extends (...args: any[]) => any>(
  fn: T,
  params: Record<string, unknown>,
  options: ExecOptions = {}
): Promise<ReturnType<T>> {
  let processedParams: Record<string, unknown> | null = null;
  let result: ReturnType<T>;
  
  try {
    // Process parameters, replacing @vhsm placeholders with actual values
    processedParams = await processParams(params, options);
    
    // Extract sensitive values for cleanup
    const sensitiveValues = (processedParams as any).__sensitiveValues as string[] || [];
    delete (processedParams as any).__sensitiveValues;
    
    // Execute the function
    result = await fn(processedParams);
    
    // Clear sensitive values from memory immediately after execution
    for (const value of sensitiveValues) {
      if (typeof value === 'string') {
        clearString(value);
      }
    }
    
    // Also clear any sensitive values from processedParams
    for (const [key, value] of Object.entries(processedParams)) {
      if (typeof value === 'string' && params[key] && typeof params[key] === 'string' && (params[key] as string).startsWith('@vhsm ')) {
        clearString(value as string);
      }
    }
    
    return result;
  } catch (error) {
    // Clear sensitive data even on error
    if (processedParams) {
      const sensitiveValues = (processedParams as any).__sensitiveValues as string[] || [];
      for (const value of sensitiveValues) {
        if (typeof value === 'string') {
          clearString(value);
        }
      }
      
      for (const [key, value] of Object.entries(processedParams)) {
        if (typeof value === 'string' && params[key] && typeof params[key] === 'string' && (params[key] as string).startsWith('@vhsm ')) {
          clearString(value as string);
        }
      }
    }
    
    throw error;
  }
}

