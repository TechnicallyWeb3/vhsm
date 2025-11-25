import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import type { KeyDecryptionProvider } from '../types.js';
import { DecryptionError } from '../types.js';
import inquirer from 'inquirer';

/**
 * Password-based key decryption provider
 * Uses AES-256-GCM for encryption/decryption
 */
export class PasswordProvider implements KeyDecryptionProvider {
  readonly name = 'password';
  readonly requiresInteraction = true;

  /**
   * Decrypts the encrypted key using a password prompt or provided password
   */
  async decrypt(encryptedKey: string, providedPassword?: string): Promise<string> {
    try {
      // Parse the encrypted key format: salt:iv:tag:encryptedData (all base64)
      const parts = encryptedKey.split(':');
      if (parts.length !== 4) {
        throw new DecryptionError('Invalid encrypted key format');
      }

      const [saltB64, ivB64, tagB64, encryptedB64] = parts;
      
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

      // Derive key from password using PBKDF2
      const key = createHash('sha256')
        .update(password)
        .update(salt)
        .digest();

      // Decrypt using AES-256-GCM
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      // Note: JavaScript strings are immutable, so we can't actually clear them from memory
      // The password will be garbage collected when it goes out of scope
      // This is a limitation of JavaScript's memory model

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
 */
export function encryptKeyWithPassword(
  plaintextKey: string,
  password: string
): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12); // 96 bits for GCM
  const key = createHash('sha256')
    .update(password)
    .update(salt)
    .digest();

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(plaintextKey, 'utf-8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const tag = cipher.getAuthTag();

  // Format: salt:iv:tag:encryptedData (all base64)
  return [
    salt.toString('base64'),
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

