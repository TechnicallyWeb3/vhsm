import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { loadConfig } from '../../config.js';
import { listProviders, getProvider } from '../../providers/index.js';
import type { ProviderConfig } from '../../types.js';
import { 
  parseEncryptedKeys,
  spawnDotenvx,
  isPatternInGitignore,
  addPatternToGitignore
} from '../utils.js';

export async function encryptKey(
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
  // Validate provider
  const config = loadConfig();
  const availableProviders = listProviders();
  if (!availableProviders.includes(providerName)) {
    throw new Error(`Unknown provider: ${providerName}. Available providers: ${availableProviders.join(', ')}`);
  }
  
  // Prompt for password early if using password provider and no password provided
  let finalPassword = providedPassword;
  
  // DPAPI doesn't support password parameter
  if (providerName !== 'password' && providedPassword) {
    console.warn('⚠️  Password parameter is ignored when not using password provider');
  }
  if (providerName === 'password' && !finalPassword) {
    const inquirer = (await import('inquirer')).default;
    const prompt = await inquirer.prompt([
      {
        type: 'password',
        name: 'password',
        message: 'Enter passphrase to encrypt keys:',
        mask: '*',
        validate: (input: string) => {
          if (!input || input.length === 0) {
            return 'Passphrase cannot be empty';
          }
          if (input.length < 8) {
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
    finalPassword = prompt.password;
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
  // Use the unified provider interface for validation
  const provider = getProvider(providerName);
  let validatedConfig: ProviderConfig | undefined;
  
  // Build initial config from provided options
  const initialConfig: ProviderConfig = {};
  if (finalPassword && (providerName === 'password' || providerName === 'tpm2')) {
    initialConfig.password = finalPassword;
    if (providerName === 'tpm2') {
      initialConfig.authPassword = finalPassword;
    }
  }
  
  // Validate encryption using provider's validateEncryption method
  if (provider.validateEncryption) {
    try {
      validatedConfig = await provider.validateEncryption(initialConfig, existingKeys) as ProviderConfig | undefined;
    } catch (error) {
      throw new Error(`Provider validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  } else {
    validatedConfig = initialConfig;
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

  // Encrypt using the unified provider interface
  console.log(`Encrypting keys with ${providerName}...`);
  
  // Determine provider prefix for the output format
  const providerPrefix = providerName === 'password' ? 'encrypted' : providerName;
  
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
      console.log(`Encrypting key ${index + 1}/${keyValues.length}: ${keyKeys[index]}...`);
      
      // Use the unified provider interface
      const encrypted = await provider.encrypt(key, validatedConfig);
      const encapsulatedKey = `${vhsmKey}=${providerPrefix}:${encrypted}`;
      outputContent += `\n${encapsulatedKey}`;
    }
    
    if (keysToEncrypt.length > 1) {
      console.log(`\n✅ All ${keysToEncrypt.length} key(s) encrypted.`);
    }
  }

  // Write to file
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

