import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { loadConfig } from '../../config.js';
import { listProviders, getProvider } from '../../providers/index.js';
import type { ProviderConfig } from '../../types.js';
import { 
  parseEncryptedKeys,
  spawnDotenvx,
  isPatternInGitignore,
  addPatternToGitignore,
  getEnvSuffix
} from '../utils.js';

export async function encryptKey(
  keyFile: string, 
  outputPath: string, 
  providerName: string = loadConfig().provider || 'password',
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
  // Load configuration (including password timeout)
  const config = loadConfig();

  // Validate provider
  const availableProviders = listProviders();
  if (!availableProviders.includes(providerName)) {
    throw new Error(`Unknown provider: ${providerName}. Available providers: ${availableProviders.join(', ')}`);
  }
  
  // Get provider to check password mode
  const provider = getProvider(providerName);

  // Warn if password is provided but provider doesn't support it
  if (providedPassword && provider.passwordMode === 'none') {
    console.warn(`⚠️  Password parameter is ignored when using ${providerName} provider (does not support passwords)`);
  }

  // Step 1: Check if encrypted file already exists and verify provider and password match BEFORE running dotenvx
  let existingEncryptedContent: string | null = null;
  let existingKeys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }> = [];
  const encryptedFileExists = existsSync(outputPath);

  if (encryptedFileExists) {
    existingEncryptedContent = readFileSync(outputPath, 'utf-8').trim();
    existingKeys = parseEncryptedKeys(existingEncryptedContent);
  }

  // Use the unified provider interface for validation
  let validatedConfig: ProviderConfig | undefined;
  let initialConfig: ProviderConfig = {};
  initialConfig.password = providedPassword;
  if (config.passwordTimeout) {
    initialConfig.passwordTimeout = config.passwordTimeout;
  }

  if (existingKeys.length > 0) {
    // Re-encryption flow: validate against existing keys, then run dotenvx
    // Check if any existing keys use a different provider
    const existingProviders = new Set(existingKeys.map(k => k.provider));
    const uniqueProviders = Array.from(existingProviders);
    
    // If there's a provider mismatch, show helpful error and fail early
    if (uniqueProviders.length > 0 && !uniqueProviders.includes(providerName)) {
      const currentProvider = uniqueProviders[0]; // Use first provider found
      
      console.error(`\n❌ Provider mismatch detected!`);
      console.error(`   Current encrypted keys use provider: ${currentProvider}`);
      console.error(`   You requested provider: ${providerName}`);
      console.error(`\n   To change providers, you must:`);
      console.error(`   1. Decrypt the existing keys: vhsm decrypt --restore`);
      console.error(`   2. Re-encrypt with the new provider: vhsm encrypt -p ${providerName}`);
      console.error(`\n   Or use the correct command:`);
      console.error(`   vhsm encrypt (provider auto-detected)\n`);
      
      throw new Error(`Cannot encrypt with provider '${providerName}'. Existing encrypted keys use provider '${currentProvider}'.`);
    }
    // Validate encryption will succeed BEFORE running dotenvx encrypt
    // This ensures we don't create .env.keys if encryption will fail
    if (provider.validateEncryption) {
      try {
        validatedConfig = await provider.validateEncryption(initialConfig, existingKeys) as ProviderConfig | undefined;
      } catch (error) {
        throw new Error(`Provider validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    } else {
      validatedConfig = initialConfig;
    }
  } else {
    // First-time encryption flow: encrypt test key, validate, then run dotenvx
    // Step 1: Test encrypt with dummy data to ensure encryption works
    // console.log('Testing encryption setup...');
    const testKey = 'test-validation-key';
    let testEncrypted: string;
    
    try {
      // This will prompt for password if not provided
      testEncrypted = await provider.encrypt(testKey, initialConfig);
    } catch (error) {
      throw new Error(`Encryption test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
    
    // Step 2: Validate encryption using validateEncryption
    if (provider.validateEncryption) {
      try {
        // Add the test encrypted key to validate it can be decrypted
        const testKeys = [{ provider: providerName, encryptedValue: testEncrypted }];
        validatedConfig = await provider.validateEncryption(initialConfig, testKeys) as ProviderConfig | undefined;
        if (!validatedConfig) {
          validatedConfig = initialConfig;
        }
        // console.log('✅ Encryption setup validated');
      } catch (error) {
        throw new Error(`Encryption validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    } else {
      validatedConfig = initialConfig;
    }
  }

  const envKeysFile = dotenvxOptions?.envKeysFile || keyFile;
  const envFiles = dotenvxOptions?.envFile || ['.env'];

  // TODO: Combine the logic of encrypting JSON files with the logic of encrypting environment variables in the same function
  // Check if any of the env files are JSON files and encrypt them using the similar
  // logic as the encryptJsonFile function: 
  // 1. add json content to env file and encrypt the json data using dotenvx


  // Step 2.75: Decrypt existing VHSM_PRIVATE_KEY to get DOTENV_PRIVATE_KEY for dotenvx
  // This allows dotenvx encrypt to use existing keys instead of creating new .env.keys file
  // This is especially useful when re-encrypting with the same password
  // According to dotenvx docs: "set your DOTENV_PRIVATE_KEY ahead of your dotenvx run command"
  let decryptedKeysMap: Map<string, string> = new Map();
  
  if (existingKeys.length > 0) {
    // Use validatedConfig if available, otherwise use initialConfig
    const configToUse = validatedConfig || initialConfig;
    
    // Get the env files we're encrypting to determine which keys we need
    const envFiles = dotenvxOptions?.envFile || ['.env'];
    
    // Try to decrypt each VHSM_PRIVATE_KEY that matches the env files we're encrypting
    for (const envFile of envFiles) {
      const suffix = getEnvSuffix(envFile);
      const vhsmKeyName = `VHSM_PRIVATE_KEY${suffix}`;
      const dotenvKeyName = `DOTENV_PRIVATE_KEY${suffix}`;
      
      // Find the matching encrypted key (must match provider)
      const existingKey = existingKeys.find(k => k.vhsmKey === vhsmKeyName && k.provider === providerName);
      
      if (existingKey && configToUse) {
        try {
          // Decrypt the VHSM_PRIVATE_KEY to get the DOTENV_PRIVATE_KEY value
          const decryptedKey = await provider.decrypt(existingKey.encryptedValue, configToUse);
          decryptedKeysMap.set(dotenvKeyName, decryptedKey);
        } catch (error) {
          // If decryption fails, that's okay - we'll let dotenvx create new keys
          // This can happen if the password is wrong (but validation should have caught that)
          // or if there's a provider-specific issue
          console.warn(`⚠️  Could not decrypt ${vhsmKeyName} to inject into dotenvx: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
    }
  }

  // Prepare environment with decrypted keys (if any)
  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
  };
  
  for (const [key, value] of decryptedKeysMap.entries()) {
    env[key] = value;
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
    env,
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

  // Step 3: Get the keys to encrypt
  // If .env.keys file exists, read from it
  // Otherwise, use the decrypted keys we already have (from DOTENV_PRIVATE_KEY env vars)
  let keyKeys: string[] = [];
  let keyValues: string[] = [];
  const keyFileExists = existsSync(keyFile);
  
  if (keyFileExists) {
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
    keyKeys = keyLines.map(line => line.split('=')[0].trim());
    keyValues = keyLines.map(line => line.split('=').slice(1).join('=').trim());
  } else {
    // .env.keys file doesn't exist - this is expected when DOTENV_PRIVATE_KEY is provided via env var
    // Use the decrypted keys we already have
    if (decryptedKeysMap.size === 0) {
      throw new Error(`Missing keys file: ${keyFile}. dotenvx encrypt should have created it, or you need to provide DOTENV_PRIVATE_KEY via environment variable.`);
    }
    
    // Convert decrypted keys map to arrays
    const envFiles = dotenvxOptions?.envFile || ['.env'];
    
    for (const envFile of envFiles) {
      const suffix = getEnvSuffix(envFile);
      const dotenvKeyName = `DOTENV_PRIVATE_KEY${suffix}`;
      const decryptedKey = decryptedKeysMap.get(dotenvKeyName);
      
      if (decryptedKey) {
        keyKeys.push(dotenvKeyName);
        keyValues.push(decryptedKey);
      }
    }
    
    if (keyKeys.length === 0) {
      throw new Error(`No decrypted keys available. Could not find matching DOTENV_PRIVATE_KEY for the specified env files.`);
    }
    
    console.log(`ℹ️  Using existing decrypted keys (${keyFile} not created - this is expected when DOTENV_PRIVATE_KEY is provided)`);
  }
  
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
        // Get the provider for the existing key to determine its output prefix
        const existingProvider = getProvider(existingKey.provider);
        const existingPrefix = existingProvider.outputPrefix || existingKey.provider;
        outputContent += `\n${existingKey.vhsmKey}=${existingPrefix}:${existingKey.encryptedValue}`;
      }
    }
  }

  // Encrypt using the unified provider interface
  // console.log(`Encrypting keys with ${providerName}...`);
  
  // Determine provider prefix for the output format (use provider's outputPrefix or fallback to name)
  const providerPrefix = provider.outputPrefix || providerName;
  
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
    for (const { index, key, vhsmKey } of keysToEncrypt) {
      // console.log(`Encrypting key ${index + 1}/${keyValues.length}: ${keyKeys[index]}...`);
      
      // Use the unified provider interface
      // Use validatedConfig if available, otherwise fall back to initialConfig (which has the password)
      const configToUse = validatedConfig || initialConfig;
      
      // Encrypt the key
      const encrypted = await provider.encrypt(key, configToUse);
      
      // Verify encryption using validateEncryption with the newly encrypted key
      if (provider.validateEncryption) {
        try {
          // Add the newly encrypted key to existing keys for validation
          const testKeys = [...existingKeys, { provider: providerName, encryptedValue: encrypted }];
          await provider.validateEncryption(configToUse, testKeys);
          console.log(`✅ ${keyKeys[index]} verified`);
        } catch (error) {
          throw new Error(`${keyKeys[index]} verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      } else {
        // If provider doesn't have validateEncryption, skip verification
        console.log(`⚠️  Skipping verification for ${keyKeys[index]} (provider does not support validateEncryption)`);
      }
      
      // Only add to output after successful verification
      const encapsulatedKey = `${vhsmKey}=${providerPrefix}:${encrypted}`;
      outputContent += `\n${encapsulatedKey}`;
    }
    
    if (keysToEncrypt.length > 1) {
      console.log(`\n✅ All ${keysToEncrypt.length} key(s) encrypted and verified.`);
    }
  }

  // Write to file
  writeFileSync(outputPath, outputContent, { mode: 0o600 }); // Read/write for owner only

  console.log(`VHSM encrypted keys written to: ${outputPath}`);
  console.log('Make sure to secure this file and never commit it to version control. More tests need to be done before these files are safe to commit.');
  
  // Delete the original .env.keys file if requested and it exists
  if (shouldDelete && keyFileExists) {
    try {
      unlinkSync(keyFile);
      // console.log(`Deleted original key file: ${keyFile}`);
    } catch (error) {
      console.warn(`Warning: Could not delete original key file: ${keyFile}`);
    }
  }

  
  // Step 2.5: Check and optionally add files to .gitignore
  const gitignorePath = '.gitignore';
  
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
      console.warn(`⚠️  ${file.displayName} (${file.type}) is not in .gitignore, add it manually or use: vhsm encrypt -gi ${file.name}`);
    }
  }
  
  // Note: JavaScript strings are immutable, so we can't actually clear them from memory
  // The passwords will be garbage collected when they go out of scope
}

