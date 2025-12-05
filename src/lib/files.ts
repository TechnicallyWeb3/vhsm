/**
 * vHSM File Operations - Secure JSON file encryption and decryption
 * 
 * Provides functions to encrypt and decrypt JSON files using vHSM keys
 */

import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { getProvider } from '../providers/index.js';
import { loadConfig } from '../config.js';
import { 
  loadEncryptedKeyFile, 
  parseEncryptedKeys, 
  matchKeysToEnvFiles,
  spawnDotenvx,
  getEnvSuffix
} from '../cli/utils.js';
import { SessionCache } from '../cache.js';
import { createKeyId, clearString } from '../security.js';
import { config as dotenvxConfig } from '@dotenvx/dotenvx';

// Cache for decrypted file contents
const fileCache = new SessionCache();

/**
 * Options for JSON file encryption
 */
export interface EncryptJsonOptions {
  /**
   * Provider to use for encryption
   * @default 'password' or from config
   */
  provider?: string;
  
  /**
   * Password for encryption (if using password provider)
   */
  password?: string;
  
  /**
   * Whether to delete the original unencrypted JSON file after encryption
   * @default true
   */
  deleteOriginal?: boolean;
  
  /**
   * Output path for encrypted file
   * @default '[filename].encrypted.json'
   */
  outputPath?: string;
  
  /**
   * Path to encrypted keys file
   * @default '.env.keys.encrypted'
   */
  encryptedKeysFile?: string;
}

/**
 * Options for JSON file decryption/loading
 */
export interface LoadFileOptions {
  /**
   * Path to encrypted private key file
   * @default '.env.keys.encrypted'
   */
  encryptedKeysFile?: string;
  
  /**
   * Provider name to use for decryption
   */
  provider?: string;
  
  /**
   * Password for decryption (if using password provider)
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
}

/**
 * Structure of an encrypted JSON file
 */
interface EncryptedJsonFile {
  encryptedBy: string;
  version: string;
  encryptedValue: string;
}

/**
 * Normalize JSON key name to environment variable format
 * example.json -> EXAMPLE_JSON
 * data/config.json -> CONFIG_JSON
 */
function jsonFileToEnvKey(filePath: string): string {
  const fileName = basename(filePath, '.json');
  return fileName.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_JSON';
}

/**
 * Get VHSM key name from env key
 * TEST_JSON -> VHSM_PRIVATE_KEY_TEST_JSON
 */
function envKeyToVhsmKey(envKey: string): string {
  return `VHSM_PRIVATE_KEY_${envKey}`;
}

/**
 * Get DOTENV key name from env key
 * TEST_JSON -> DOTENV_PRIVATE_KEY_TEST_JSON
 */
function envKeyToDotenvKey(envKey: string): string {
  return `DOTENV_PRIVATE_KEY_${envKey}`;
}

/**
 * Get the version from package.json
 */
function getPackageVersion(): string {
  try {
    const packageJsonPath = join(dirname(new URL(import.meta.url).pathname), '..', '..', 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Encrypt a JSON file using vHSM
 * 
 * Creates a .env.[filename].json file with the reference, encrypts both the .env file
 * and the JSON content using the same key, then saves as [filename].encrypted.json
 * 
 * @param jsonFilePath - Path to the JSON file to encrypt
 * @param options - Encryption options
 */
export async function encryptJsonFile(
  jsonFilePath: string,
  options: EncryptJsonOptions = {}
): Promise<void> {
  // Validate input file exists
  if (!existsSync(jsonFilePath)) {
    throw new Error(`JSON file not found: ${jsonFilePath}`);
  }
  
  // Read and validate JSON
  let jsonContent: string;
  try {
    jsonContent = readFileSync(jsonFilePath, 'utf-8');
    JSON.parse(jsonContent); // Validate it's valid JSON
  } catch (error) {
    throw new Error(`Invalid JSON file: ${jsonFilePath}. ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
  
  const config = loadConfig();
  const providerName = options.provider || config.provider || 'password';
  const provider = getProvider(providerName);
  const deleteOriginal = options.deleteOriginal !== false; // Default true
  const version = getPackageVersion();
  
  // Generate env key name and file paths
  const envKey = jsonFileToEnvKey(jsonFilePath);
  const vhsmKey = envKeyToVhsmKey(envKey);
  const dotenvKeyName = envKeyToDotenvKey(envKey);
  const fileName = basename(jsonFilePath, '.json');
  const fileDir = dirname(jsonFilePath);
  const outputPath = options.outputPath || join(fileDir, `${fileName}.encrypted.json`);
  const envFilePath = join(fileDir, `.env.${fileName}.json`);
  const envKeysPath = join(fileDir, `.env.keys.${fileName}.json`);
  const encryptedKeysFile = options.encryptedKeysFile || '.env.keys.encrypted';
  
  const isDebug = process.env.VHSM_DEBUG === 'true';
  
  if (isDebug) {
    console.log(`🔐 Encrypting JSON file: ${jsonFilePath}`);
    console.log(`   Provider: ${providerName}`);
    console.log(`   Output: ${outputPath}`);
    console.log(`   Env key: ${envKey}`);
  }
  
  // Step 1: Create .env.[filename].json file with JSON content
  // This allows us to use dotenvx encryption format and get the right key name
  // Convert JSON to single line to avoid issues with .env format
  const jsonSingleLine = JSON.stringify(JSON.parse(jsonContent));
  const envContent = `${envKey}=${jsonSingleLine}`;
  writeFileSync(envFilePath, envContent, { mode: 0o644 });
  
  // Step 2: Run dotenvx encrypt to encrypt the JSON content and generate key
  if (isDebug) {
    console.log(`🔑 Running dotenvx encrypt...`);
  }
  const dotenvxArgs = ['encrypt', '-q', '-f', envFilePath, '-fk', envKeysPath];
  
  const dotenvxEncrypt = spawnDotenvx(dotenvxArgs, {
    stdio: 'pipe',
    shell: process.platform === 'win32',
  });
  
  const encryptExitCode = await new Promise<number>((resolve) => {
    dotenvxEncrypt.on('exit', (code) => resolve(code ?? 0));
    dotenvxEncrypt.on('error', (error) => {
      console.error(`Failed to run dotenvx encrypt: ${error.message}`);
      resolve(1);
    });
  });
  
  if (encryptExitCode !== 0) {
    throw new Error('dotenvx encrypt failed');
  }
  
  if (isDebug) {
    console.log(`✅ JSON content encrypted`);
  }
  
  // Step 3: Read the encrypted value from the .env file
  const encryptedEnvContent = readFileSync(envFilePath, 'utf-8');
  const encryptedMatch = new RegExp(`${envKey}=(encrypted:[^\\n]+)`).exec(encryptedEnvContent);
  if (!encryptedMatch) {
    throw new Error('Failed to extract encrypted JSON content');
  }
  
  const encryptedJsonValue = encryptedMatch[1];
  
  // Step 4: Read the generated DOTENV_PRIVATE_KEY from keys file
  if (!existsSync(envKeysPath)) {
    throw new Error(`Keys file not created: ${envKeysPath}`);
  }
  
  const keysContent = readFileSync(envKeysPath, 'utf-8');
  
  // Try exact match first
  let keyMatch = new RegExp(`${dotenvKeyName}=([^\\n]+)`).exec(keysContent);
  
  // If not found, dotenvx may use different formatting (e.g., hyphens vs underscores in filename)
  // Since dotenvx creates one key per file, we can use the first (and only) key found
  if (!keyMatch) {
    // Find any DOTENV_PRIVATE_KEY in the file (dotenvx creates one per file)
    const allKeys = keysContent.match(/DOTENV_PRIVATE_KEY[^=]*=([^\n]+)/g);
    if (allKeys && allKeys.length > 0) {
      // Use the first key found
      keyMatch = /DOTENV_PRIVATE_KEY[^=]*=([^\n]+)/.exec(allKeys[0]);
    }
  }
  
  if (!keyMatch) {
    const availableKeys = keysContent.match(/DOTENV_PRIVATE_KEY[^=\n]+/g)?.join(', ') || 'none';
    throw new Error(`No ${dotenvKeyName} found in generated keys file. Available keys: ${availableKeys}`);
  }
  
  const dotenvPrivateKey = keyMatch[1].trim();
  
  // Step 5: Create the encrypted JSON file with metadata
  const encryptedJsonFile: EncryptedJsonFile = {
    encryptedBy: 'vhsm',
    version: version,
    encryptedValue: encryptedJsonValue,
  };
  
  writeFileSync(outputPath, JSON.stringify(encryptedJsonFile, null, 2), { mode: 0o644 });
  if (isDebug) {
    console.log(`✅ Created encrypted JSON: ${outputPath}`);
  }
  
  // Step 6: Update the .env file to contain reference instead of encrypted content
  const envRefContent = `${envKey}=${basename(outputPath)}`;
  writeFileSync(envFilePath, envRefContent, { mode: 0o644 });
  if (isDebug) {
    console.log(`✅ Updated ${envFilePath} with reference`);
  }
  
  // Step 7: Encrypt the DOTENV_PRIVATE_KEY using vHSM provider and add to main encrypted keys file
  const encryptedKey = await provider.encrypt(dotenvPrivateKey, options.password ? { password: options.password } : {});
  
  // Read or create the main encrypted keys file
  let encryptedKeysContent = '';
  if (existsSync(encryptedKeysFile)) {
    encryptedKeysContent = readFileSync(encryptedKeysFile, 'utf-8');
  } else {
    encryptedKeysContent = `#/-----------------!VHSM_PRIVATE_KEYS!------------------/
#/ VHSM encrypted keys. DO NOT commit to source control /
#/------------------------------------------------------/
`;
  }
  
  // Get provider prefix
  const providerPrefix = provider.outputPrefix || providerName;
  
  // Add the encrypted key
  const keyLine = `\n${vhsmKey}=${providerPrefix}:${encryptedKey}`;
  
  // Check if key already exists
  if (encryptedKeysContent.includes(`${vhsmKey}=`)) {
    // Replace existing key
    const keyRegex = new RegExp(`${vhsmKey}=[^\\n]+`, 'g');
    encryptedKeysContent = encryptedKeysContent.replace(keyRegex, `${vhsmKey}=${providerPrefix}:${encryptedKey}`);
  } else {
    // Append new key
    encryptedKeysContent += keyLine;
  }
  
  writeFileSync(encryptedKeysFile, encryptedKeysContent, { mode: 0o600 });
  if (isDebug) {
    console.log(`✅ Added ${vhsmKey} to ${encryptedKeysFile}`);
  }
  
  // Step 8: Clean up temporary keys file (delete .env.keys.[filename].json)
  if (existsSync(envKeysPath)) {
    unlinkSync(envKeysPath);
    if (isDebug) {
      console.log(`✅ Deleted temporary keys file`);
    }
  }
  
  // Step 9: Delete original file if requested
  if (deleteOriginal) {
    unlinkSync(jsonFilePath);
    if (isDebug) {
      console.log(`🗑️  Deleted original file: ${jsonFilePath}`);
    }
  }
  
  if (isDebug) {
    console.log(`\n✅ JSON file encrypted successfully!`);
    console.log(`   Encrypted file: ${outputPath}`);
    console.log(`   Env reference: ${envFilePath}`);
  }
  
  // Clear sensitive data
  clearString(dotenvPrivateKey);
}

/**
 * Decrypt and load a JSON file
 * 
 * @param jsonFilePath - Path to the encrypted JSON file
 * @param options - Decryption options
 * @returns The decrypted JSON content as an object
 */
export async function loadFile<T = any>(
  jsonFilePath: string,
  options: LoadFileOptions = {}
): Promise<T> {
  // Validate input file exists
  if (!existsSync(jsonFilePath)) {
    throw new Error(`Encrypted JSON file not found: ${jsonFilePath}`);
  }
  
  const config = loadConfig();
  const useCache = options.enableCache !== false && (config.enableCache !== false);
  const timeout = options.cacheTimeout || config.cacheTimeout || 3600000;
  
  // Check cache first
  const cacheKey = createKeyId(jsonFilePath);
  if (useCache) {
    fileCache.cleanup();
    const cached = fileCache.get(cacheKey);
    if (cached) {
      return JSON.parse(cached) as T;
    }
  }
  
  // Read and parse encrypted JSON file
  let encryptedFile: EncryptedJsonFile;
  try {
    const content = readFileSync(jsonFilePath, 'utf-8');
    encryptedFile = JSON.parse(content);
    
    if (!encryptedFile.encryptedBy || encryptedFile.encryptedBy !== 'vhsm') {
      throw new Error('File is not a vHSM encrypted JSON file');
    }
    
    if (!encryptedFile.encryptedValue || !encryptedFile.encryptedValue.startsWith('encrypted:')) {
      throw new Error('Invalid encrypted value format');
    }
  } catch (error) {
    throw new Error(`Failed to read encrypted JSON file: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
  
  // Determine which key to use
  const fileName = basename(jsonFilePath, '.encrypted.json');
  const fileDir = dirname(jsonFilePath);
  const envKey = jsonFileToEnvKey(join(fileDir, fileName + '.json'));
  const vhsmKey = envKeyToVhsmKey(envKey);
  
  // Derive dotenvx key name from the actual .env filename (preserves hyphens)
  // .env.test-decrypt.json -> DOTENV_PRIVATE_KEY_TEST-DECRYPT_JSON
  const envFileName = `.env.${fileName}.json`;
  const envFileSuffix = getEnvSuffix(envFileName);
  const dotenvKeyName = `DOTENV_PRIVATE_KEY${envFileSuffix}`;
  
  // Load the encrypted key for this JSON file
  const encryptedKeysFile = options.encryptedKeysFile || '.env.keys.encrypted';
  
  if (!existsSync(encryptedKeysFile)) {
    throw new Error(`Encrypted keys file not found: ${encryptedKeysFile}`);
  }
  
  const encryptedKeyContent = loadEncryptedKeyFile(encryptedKeysFile);
  const availableKeys = parseEncryptedKeys(encryptedKeyContent);
  
  // Find the key for this JSON file
  const keyEntry = availableKeys.find(k => k.vhsmKey === vhsmKey);
  if (!keyEntry) {
    throw new Error(`No encrypted key found for ${jsonFilePath} (looking for ${vhsmKey} in ${encryptedKeysFile})`);
  }
  
  // Decrypt the DOTENV_PRIVATE_KEY using vHSM
  const providerName = options.provider || keyEntry.provider;
  const provider = getProvider(providerName);
  
  const providerConfig = options.password ? { password: options.password } : {};
  const dotenvPrivateKey = await provider.decrypt(keyEntry.encryptedValue, providerConfig);
  
  try {
    // Create a temporary env file with the encrypted JSON value
    // Use the same .env.[filename].json pattern so dotenvx can find the right key
    const tempEnvPath = join(fileDir, `.env.${fileName}.json`);
    const tempEnvContent = `${envKey}=${encryptedFile.encryptedValue}`;
    
    // Backup the existing .env file if it exists
    let existingEnvContent: string | null = null;
    if (existsSync(tempEnvPath)) {
      existingEnvContent = readFileSync(tempEnvPath, 'utf-8');
    }
    
    writeFileSync(tempEnvPath, tempEnvContent, { mode: 0o644 });
    
    try {
      // Set the decrypted key in process.env for dotenvx to find
      const originalProcessEnv = process.env[dotenvKeyName];
      process.env[dotenvKeyName] = dotenvPrivateKey;
      
      // Load and decrypt using dotenvx
      const processEnv: Record<string, string> = { 
        ...process.env as Record<string, string>,
      };
      
      const configResult = dotenvxConfig({
        path: tempEnvPath,
        processEnv: processEnv,
        strict: false,
        quiet: true,
      });
      
      // Restore original value
      if (originalProcessEnv !== undefined) {
        process.env[dotenvKeyName] = originalProcessEnv;
      } else {
        delete process.env[dotenvKeyName];
      }
      
      if (configResult.error && !configResult.error.message.includes('MISSING_ENV_FILE')) {
        throw configResult.error;
      }
      
      const decryptedValue = processEnv[envKey];
      if (!decryptedValue) {
        throw new Error('Failed to decrypt JSON content');
      }
      
      // Parse the JSON
      const jsonObject = JSON.parse(decryptedValue);
      
      // Cache the result
      if (useCache) {
        fileCache.set(cacheKey, decryptedValue, timeout);
      }
      
      // Restore the original .env file
      if (existingEnvContent !== null) {
        writeFileSync(tempEnvPath, existingEnvContent, { mode: 0o644 });
      }
      
      return jsonObject as T;
    } catch (error) {
      // Restore the original .env file on error
      if (existingEnvContent !== null && existsSync(tempEnvPath)) {
        writeFileSync(tempEnvPath, existingEnvContent, { mode: 0o644 });
      }
      throw error;
    }
  } finally {
    // Clear sensitive data
    clearString(dotenvPrivateKey);
  }
}

/**
 * Get a value from a JSON file using dot notation
 * 
 * @param jsonFilePath - Path to the encrypted JSON file
 * @param path - Dot notation path to the value (e.g., 'user.name')
 * @param options - Decryption options
 * @returns The value at the specified path
 */
export async function getJsonValue<T = any>(
  jsonFilePath: string,
  path: string,
  options: LoadFileOptions = {}
): Promise<T> {
  const jsonObject = await loadFile(jsonFilePath, options);
  
  // Navigate the path
  const parts = path.split('.');
  let current: any = jsonObject;
  
  for (const part of parts) {
    if (current === null || current === undefined) {
      throw new Error(`Path '${path}' not found in JSON file`);
    }
    
    if (typeof current !== 'object' || !(part in current)) {
      throw new Error(`Path '${path}' not found in JSON file`);
    }
    
    current = current[part];
  }
  
  return current as T;
}

