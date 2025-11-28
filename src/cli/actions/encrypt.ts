import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { loadConfig } from '../../config.js';
import { listProviders } from '../../providers/index.js';
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
    const { encryptKeyWithFIDO2 } = await import('../../providers/fido2.js');
    
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
    const { encryptKeyWithPassword, PasswordProvider } = await import('../../providers/password.js');
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
    const { encryptKeyWithTPM2 } = await import('../../providers/tpm2.js');
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
    const { encryptKeyWithDPAPI } = await import('../../providers/dpapi.js');
    
    console.log('Encrypting keys with Windows DPAPI...');
    for (const [i, key] of keyValues.entries()) {
      const encrypted = encryptKeyWithDPAPI(key);
      const encapsulatedKey = `${keyKeys[i].replace('DOTENV_', 'VHSM_')}=dpapi:${encrypted}`;
      outputContent += `\n${encapsulatedKey}`;
    }
  } else if (providerName === 'fido2') {
    // FIDO2 encryption - credential already validated and created if needed
    const { encryptKeyWithFIDO2 } = await import('../../providers/fido2.js');
    
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
    const { encryptKeyWithTPM2 } = await import('../../providers/tpm2.js');
    
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
    const { encryptKeyWithPassword } = await import('../../providers/password.js');
    
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

