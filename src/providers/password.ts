import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import type { Provider, KeyDecryptionProvider, ProviderConfig } from '../types.js';
import { DecryptionError } from '../types.js';
import inquirer from 'inquirer';
import argon2 from 'argon2';

// KDF version identifiers
const KDF_VERSION_SHA256 = 'sha256'; // Legacy format (backward compatibility)
const KDF_VERSION_ARGON2ID = 'argon2id'; // New default format

// Argon2id parameters (OWASP recommended)
const ARGON2_MEMORY_COST = 65536; // 64 MB
const ARGON2_TIME_COST = 3; // iterations
const ARGON2_PARALLELISM = 4; // threads
const ARGON2_KEYLEN = 32; // 32 bytes for AES-256

/**
 * Derives a key from a password using the specified KDF
 */
async function deriveKey(
  password: string,
  salt: Buffer,
  kdfVersion: string = KDF_VERSION_ARGON2ID
): Promise<Buffer> {
  if (kdfVersion === KDF_VERSION_ARGON2ID) {
    // Use Argon2id for new keys
    return Buffer.from(
      await argon2.hash(password, {
        type: argon2.argon2id,
        salt: salt,
        memoryCost: ARGON2_MEMORY_COST,
        timeCost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        hashLength: ARGON2_KEYLEN,
        raw: true, // Return raw buffer instead of encoded string
      })
    );
  } else if (kdfVersion === KDF_VERSION_SHA256) {
    // Legacy SHA256 for backward compatibility
    return createHash('sha256')
      .update(password)
      .update(salt)
      .digest();
  } else {
    throw new DecryptionError(`Unsupported KDF version: ${kdfVersion}`);
  }
}

/**
 * Password-based key decryption provider
 * Uses AES-256-GCM for encryption/decryption
 * Supports Argon2id (default) and SHA256 (legacy) key derivation
 */
export class PasswordProvider implements Provider, KeyDecryptionProvider {
  readonly name = 'password';
  readonly requiresInteraction = true;

  /**
   * Encrypts a plaintext key using password-based encryption
   */
  async encrypt(plaintextKey: string, config?: ProviderConfig): Promise<string> {
    let password = config?.password;
    
    // If no password provided, prompt for it
    if (!password) {
      // Check if we're in a non-interactive environment (e.g., tests)
      const isTTY = process.stdin.isTTY;
      if (!isTTY) {
        throw new Error('Password is required for encryption. Please provide it in the config or run in an interactive terminal.');
      }
      
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
      password = prompt.password;
    }
    
    // TypeScript guard: ensure password is defined
    if (!password) {
      throw new Error('Password is required for encryption');
    }
    
    if (password.length < 8) {
      throw new Error('Passphrase must be at least 8 characters');
    }
    
    return encryptKeyWithPassword(plaintextKey, password);
  }

  /**
   * Validates password before encryption
   */
  async validateEncryption(
    config?: ProviderConfig,
    existingKeys?: Array<{ provider: string; encryptedValue: string }>
  ): Promise<ProviderConfig | void> {
    const providedPassword = config?.password;
    const existingPasswordKeys = existingKeys?.filter(k => k.provider === 'password') || [];
    
    if (providedPassword) {
      if (providedPassword.length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
      }
      
      // If there are existing keys, validate password against them
      if (existingPasswordKeys.length > 0) {
        try {
          await this.decrypt(existingPasswordKeys[0].encryptedValue, providedPassword);
        } catch (error) {
          throw new Error('Password does not match existing keys');
        }
      }
      
      // Test encrypt with dummy data
      await encryptKeyWithPassword('test-validation', providedPassword);
      return { password: providedPassword };
    } else {
      // No password provided - will prompt during encryption
      if (existingPasswordKeys.length > 0) {
        // Need to validate against existing keys
        const inquirer = (await import('inquirer')).default;
        let passwordValid = false;
        let attempts = 0;
        const maxAttempts = 3;
        let validatedPassword: string | undefined;
        
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
          
          try {
            await this.decrypt(existingPasswordKeys[0].encryptedValue, passwordPrompt.password);
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
        
        return { password: validatedPassword };
      } else {
        // No existing keys - will prompt for new password during encryption
        return undefined;
      }
    }
  }

  /**
   * Decrypts the encrypted key using a password prompt or provided password
   * Supports both legacy interface (string password) and new interface (ProviderConfig)
   */
  async decrypt(encryptedKey: string, configOrPassword?: ProviderConfig | string): Promise<string> {
    // Support both old interface (string) and new interface (ProviderConfig)
    const providedPassword = typeof configOrPassword === 'string' 
      ? configOrPassword 
      : configOrPassword?.password;
    try {
      // Parse the encrypted key format
      // Old format (4 parts): salt:iv:tag:encryptedData (all base64) - uses SHA256
      // New format (5 parts): kdfVersion:salt:iv:tag:encryptedData - uses specified KDF
      const parts = encryptedKey.split(':');
      
      let kdfVersion: string;
      let saltB64: string;
      let ivB64: string;
      let tagB64: string;
      let encryptedB64: string;

      if (parts.length === 4) {
        // Old format - backward compatibility with SHA256
        [saltB64, ivB64, tagB64, encryptedB64] = parts;
        kdfVersion = KDF_VERSION_SHA256;
      } else if (parts.length === 5) {
        // New format with KDF version
        [kdfVersion, saltB64, ivB64, tagB64, encryptedB64] = parts;
        if (kdfVersion !== KDF_VERSION_SHA256 && kdfVersion !== KDF_VERSION_ARGON2ID) {
          throw new DecryptionError(`Unsupported KDF version: ${kdfVersion}`);
        }
      } else {
        throw new DecryptionError('Invalid encrypted key format');
      }
      
      const salt = Buffer.from(saltB64, 'base64');
      const iv = Buffer.from(ivB64, 'base64');
      const tag = Buffer.from(tagB64, 'base64');
      const encrypted = Buffer.from(encryptedB64, 'base64');

      // Get password from parameter or prompt
      let password: string;
      if (providedPassword) {
        password = providedPassword;
      } else {
        const prompt = await inquirer.prompt([
          {
            type: 'password',
            name: 'password',
            message: 'Enter passphrase to decrypt dotenvx private key:',
            mask: '*',
            validate: (input: string) => {
              if (!input || input.length === 0) {
                return 'Passphrase cannot be empty';
              }
              return true;
            },
          },
        ]);
        password = prompt.password;
      }

      // Derive key from password using the specified KDF
      const key = await deriveKey(password, salt, kdfVersion);

      // Decrypt using AES-256-GCM
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      // Note: JavaScript strings are immutable, so we can't actually clear them from memory
      // The password will be garbage collected when it goes out of scope
      // This is a limitation of JavaScript's memory model
      // Clear password from memory (best effort)
      // password.split('').forEach((_: string, i: number) => {
      //   (password as any)[i] = '\0';
      // });

      return decrypted.toString('utf-8');
    } catch (error) {
      if (error instanceof DecryptionError) {
        throw error;
      }
      // For debugging: log the actual error, but still throw generic message
      // In production, this would be removed or conditionally enabled
      if (process.env.VHSM_DEBUG) {
        console.error('Decryption error details:', error);
      }
      // Generic error - don't leak details
      throw new DecryptionError('Failed to decrypt key. Please check your passphrase.');
    }
  }
}

/**
 * Utility function to encrypt a key with a password
 * This is useful for initial setup
 * Uses Argon2id by default for secure key derivation
 */
export async function encryptKeyWithPassword(
  plaintextKey: string,
  password: string,
  kdfVersion: string = KDF_VERSION_ARGON2ID
): Promise<string> {
  const salt = randomBytes(16);
  const iv = randomBytes(12); // 96 bits for GCM
  
  // Derive key using the specified KDF (Argon2id by default)
  const key = await deriveKey(password, salt, kdfVersion);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(plaintextKey, 'utf-8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const tag = cipher.getAuthTag();

  // Format: kdfVersion:salt:iv:tag:encryptedData (all base64 except kdfVersion)
  return [
    kdfVersion,
    salt.toString('base64'),
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

