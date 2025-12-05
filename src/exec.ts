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
  matchKeysToEnvFiles,
  getEnvSuffix
} from './cli/utils.js';
import { config as dotenvxConfig, get as dotenvxGet } from '@dotenvx/dotenvx';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';

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

// Note: allowExec is intentionally NOT part of ExecOptions.
// This is a security design decision - exec() can only be enabled by:
// 1. Environment variable: VHSM_ALLOW_EXEC=true
// 2. Config file (.vhsmrc.json): {"allowExec": true}
// Both are admin-controlled, preventing untrusted code from enabling exec.

/**
 * Process parameters object, replacing "@vhsm KEY" strings with actual env variable values
 * and "@vhsm FILE.json path.to.value" with JSON file values
 * 
 * Simple detection logic:
 * - If no @vhsm params, just pass through (no processing needed)
 * - For env vars: Check if already in process.env, if yes use it. If not, try decryption.
 * - For JSON: Check if plain .json exists, if yes use it. If not, try encrypted version.
 * - If decryption needed but fails, return undefined with warning
 */
async function processParams(
  params: Record<string, unknown>,
  options: ExecOptions
): Promise<Record<string, unknown>> {
  const processed: Record<string, unknown> = {};
  const sensitiveValues: string[] = [];
  
  // Collect @vhsm params that need processing
  const vhsmEnvParams: Array<{ paramKey: string; envKey: string }> = [];
  const vhsmJsonParams: Array<{ paramKey: string; jsonKey: string; path?: string }> = [];
  
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string' && value.startsWith('@vhsm ')) {
      const vhsmValue = value.slice(6).trim();
      const parts = vhsmValue.split(/\s+/);
      const envKey = parts[0];
      const additionalArg = parts.slice(1).join(' ');
      
      if (envKey.endsWith('_JSON')) {
        vhsmJsonParams.push({ paramKey: key, jsonKey: envKey, path: additionalArg || undefined });
      } else {
        vhsmEnvParams.push({ paramKey: key, envKey });
      }
    }
  }
  
  // If no @vhsm params, just pass through all params directly
  if (vhsmEnvParams.length === 0 && vhsmJsonParams.length === 0) {
    for (const [key, value] of Object.entries(params)) {
      if (value instanceof Promise) {
        const resolvedValue = await value;
        processed[key] = resolvedValue;
        if (typeof resolvedValue === 'string') {
          sensitiveValues.push(resolvedValue);
        }
      } else {
        processed[key] = value;
      }
    }
    (processed as any).__sensitiveValues = sensitiveValues;
    return processed;
  }
  
  // Determine base directory for resolving paths
  const encryptedKeysFile = options.encryptedKeysFile || '.env.keys.encrypted';
  const baseDir = existsSync(encryptedKeysFile) ? dirname(resolve(encryptedKeysFile)) : process.cwd();
  
  // Track if we've loaded decrypted env vars (lazy loading)
  let decryptedEnvLoaded = false;
  let decryptedProcessEnv: Record<string, string> = {};
  
  /**
   * Lazy load decrypted env vars only when needed
   */
  async function ensureDecryptedEnv(envFile: string): Promise<void> {
    if (decryptedEnvLoaded) return;
    
    // Resolve env file path
    let resolvedEnvFile = envFile;
    if (!resolvedEnvFile.startsWith('/') && !resolvedEnvFile.match(/^[A-Z]:/)) {
      resolvedEnvFile = resolve(baseDir, resolvedEnvFile);
    }
    
    // Try to get decryption key
    let decryptedKey: string | null = null;
    try {
      decryptedKey = await getDecryptedKey(
        options.encryptedKeysFile,
        resolvedEnvFile,
        options.provider,
        options.password,
        options.enableCache,
        options.cacheTimeout
      );
    } catch {
      // Decryption failed - will use process.env values or warn below
    }
    
    // Load env vars using dotenvx
    decryptedProcessEnv = { ...process.env as Record<string, string> };
    
    if (decryptedKey) {
      const envSuffix = getEnvSuffix(basename(resolvedEnvFile));
      const dotenvKeyName = `DOTENV_PRIVATE_KEY${envSuffix}`;
      decryptedProcessEnv[dotenvKeyName] = decryptedKey;
    }
    
    const configResult = dotenvxConfig({
      path: resolvedEnvFile,
      processEnv: decryptedProcessEnv,
      envKeysFile: options.envKeysFile,
      strict: false,
      quiet: true,
    });
    
    // Clean up decrypted key
    if (decryptedKey) {
      clearString(decryptedKey);
    }
    
    decryptedEnvLoaded = true;
  }
  
  // Process all parameters
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string' && value.startsWith('@vhsm ')) {
      const vhsmValue = value.slice(6).trim();
      const parts = vhsmValue.split(/\s+/);
      const envKey = parts[0];
      const additionalArg = parts.slice(1).join(' ');
      
      if (envKey.endsWith('_JSON')) {
        // JSON file handling
        const jsonFileName = envKey.replace(/_JSON$/, '').toLowerCase();
        
        // Try plain JSON first, then encrypted
        const plainPath = join(baseDir, `${jsonFileName}.json`);
        const encryptedPath = join(baseDir, `${jsonFileName}.encrypted.json`);
        
        let jsonFilePath: string | null = null;
        let usePlainJson = false;
        
        if (existsSync(plainPath)) {
          jsonFilePath = plainPath;
          usePlainJson = true;
        } else if (existsSync(encryptedPath)) {
          jsonFilePath = encryptedPath;
          usePlainJson = false;
        } else {
          // Check for .env.[name].json reference file
          const envRefFile = join(baseDir, `.env.${jsonFileName}.json`);
          if (existsSync(envRefFile)) {
            const envContent = readFileSync(envRefFile, 'utf-8');
            const envLine = envContent.split('\n').find(line => line.trim().startsWith(`${envKey}=`));
            if (envLine) {
              const fileName = envLine.split('=')[1]?.trim();
              if (fileName) {
                jsonFilePath = join(dirname(envRefFile), fileName);
                usePlainJson = !fileName.includes('.encrypted.');
              }
            }
          }
        }
        
        if (!jsonFilePath || !existsSync(jsonFilePath)) {
          console.warn(`⚠️  JSON file not found for ${envKey}. Setting to undefined.`);
          processed[key] = undefined;
          continue;
        }
        
        try {
          if (usePlainJson) {
            // Load plain JSON directly
            const content = readFileSync(jsonFilePath, 'utf-8');
            const jsonData = JSON.parse(content);
            
            if (additionalArg) {
              // Navigate to nested path
              const pathParts = additionalArg.split('.');
              let current: any = jsonData;
              for (const part of pathParts) {
                if (current === null || current === undefined || !(part in current)) {
                  throw new Error(`Path '${additionalArg}' not found`);
                }
                current = current[part];
              }
              processed[key] = current;
              if (typeof current === 'string') {
                sensitiveValues.push(current);
              }
            } else {
              processed[key] = jsonData;
            }
          } else {
            // Use loadFile for encrypted JSON
            const { loadFile, getJsonValue } = await import('./lib/files.js');
            
            if (additionalArg) {
              const jsonValue = await getJsonValue(jsonFilePath, additionalArg, {
                encryptedKeysFile: options.encryptedKeysFile,
                provider: options.provider,
                password: options.password,
                enableCache: options.enableCache,
                cacheTimeout: options.cacheTimeout,
              });
              processed[key] = jsonValue;
              if (typeof jsonValue === 'string') {
                sensitiveValues.push(jsonValue);
              }
            } else {
              const jsonData = await loadFile(jsonFilePath, {
                encryptedKeysFile: options.encryptedKeysFile,
                provider: options.provider,
                password: options.password,
                enableCache: options.enableCache,
                cacheTimeout: options.cacheTimeout,
              });
              processed[key] = jsonData;
            }
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          console.warn(`⚠️  Failed to load JSON for ${envKey}: ${message}. Setting to undefined.`);
          processed[key] = undefined;
        }
      } else {
        // Regular environment variable
        // First check if already available in process.env
        if (process.env[envKey] !== undefined) {
          processed[key] = process.env[envKey];
          if (typeof process.env[envKey] === 'string') {
            sensitiveValues.push(process.env[envKey]!);
          }
        } else {
          // Try to load from .env file (may require decryption)
          const envFile = options.envFile || '.env';
          try {
            await ensureDecryptedEnv(envFile);
            
            const envValue = decryptedProcessEnv[envKey];
            if (envValue !== undefined) {
              processed[key] = envValue;
              if (typeof envValue === 'string') {
                sensitiveValues.push(envValue);
              }
            } else {
              console.warn(`⚠️  Environment variable '${envKey}' not found. Setting to undefined.`);
              processed[key] = undefined;
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.warn(`⚠️  Failed to get '${envKey}': ${message}. Setting to undefined.`);
            processed[key] = undefined;
          }
        }
      }
    } else if (value instanceof Promise) {
      // Support nested exec() calls - resolve Promise values
      const resolvedValue = await value;
      processed[key] = resolvedValue;
      if (typeof resolvedValue === 'string') {
        sensitiveValues.push(resolvedValue);
      }
    } else {
      processed[key] = value;
    }
  }
  
  // Clean up decrypted env vars
  for (const envKey of Object.keys(decryptedProcessEnv)) {
    const envValue = decryptedProcessEnv[envKey];
    if (typeof envValue === 'string') {
      clearString(envValue);
    }
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
  // Security check: require allowExec to be explicitly enabled by environment/config
  // Note: allowExec cannot be set via options - this is a security design decision
  // to prevent untrusted code from enabling exec programmatically
  const config = loadConfig();
  const allowExec = config.allowExec ?? false;
  
  if (!allowExec) {
    throw new Error(
      'vhsm.exec() is disabled by default for security. ' +
      'To enable, set VHSM_ALLOW_EXEC=true environment variable or ' +
      'add "allowExec": true to your .vhsmrc.json config file. ' +
      'Note: exec cannot be enabled programmatically for security reasons.'
    );
  }
  
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

