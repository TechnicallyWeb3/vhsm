import { execSync } from 'node:child_process';
import { platform } from 'node:os';
import type { Provider, KeyDecryptionProvider, ProviderConfig } from '../types.js';
import { DecryptionError } from '../types.js';

/**
 * Windows DPAPI (Data Protection API) key decryption provider
 * Uses Windows built-in encryption tied to the user account
 * 
 * Note: This provider only works on Windows systems
 */
export class DPAPIProvider implements Provider, KeyDecryptionProvider {
  readonly name = 'dpapi';
  readonly requiresInteraction = false;

  constructor() {
    // Verify we're on Windows
    if (platform() !== 'win32') {
      throw new Error('DPAPI provider is only available on Windows');
    }
  }

  /**
   * Encrypts data using Windows DPAPI
   * Returns base64-encoded encrypted data
   */
  encrypt(plaintextKey: string, _config?: ProviderConfig): string {
    if (platform() !== 'win32') {
      throw new Error('DPAPI encryption is only available on Windows');
    }

    try {
      // Escape single quotes for PowerShell
      const escapedData = plaintextKey.replace(/'/g, "''");
      
      // Create single-line PowerShell script
      const script = `Add-Type -AssemblyName System.Security; $data = [System.Text.Encoding]::UTF8.GetBytes('${escapedData}'); $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($data, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); [System.Convert]::ToBase64String($encrypted)`;

      const result = execSync(`powershell.exe -NoProfile -NonInteractive -Command "${script}"`, {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      }).trim();

      if (!result) {
        throw new Error('DPAPI encryption returned empty result');
      }

      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw new DecryptionError(`DPAPI encryption failed: ${error.message}`);
      }
      throw new DecryptionError('DPAPI encryption failed');
    }
  }

  /**
   * Validates DPAPI is ready (always succeeds on Windows)
   */
  async validateEncryption(): Promise<void> {
    if (platform() !== 'win32') {
      throw new Error('DPAPI is only available on Windows');
    }
    console.log('✅ DPAPI ready.');
  }

  /**
   * Decrypts the encrypted key using Windows DPAPI
   * The encrypted key should be base64-encoded data that was encrypted with DPAPI
   */
  async decrypt(encryptedKey: string, _configOrPassword?: ProviderConfig | string): Promise<string> {
    // Support both old interface (string) and new interface (ProviderConfig)
    // DPAPI doesn't use password/config, so we ignore it
    if (platform() !== 'win32') {
      throw new DecryptionError('DPAPI decryption is only available on Windows');
    }

    try {
      // Create single-line PowerShell script
      const script = `Add-Type -AssemblyName System.Security; $encrypted = [System.Convert]::FromBase64String('${encryptedKey}'); $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); [System.Text.Encoding]::UTF8.GetString($decrypted)`;

      const result = execSync(`powershell.exe -NoProfile -NonInteractive -Command "${script}"`, {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      }).trim();

      if (!result) {
        throw new DecryptionError('DPAPI decryption returned empty result');
      }

      return result;
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('Key not valid for use in specified state')) {
          throw new DecryptionError(
            'DPAPI decryption failed: Key was encrypted by a different user or on a different machine'
          );
        }
        throw new DecryptionError(`DPAPI decryption failed: ${error.message}`);
      }
      throw new DecryptionError('DPAPI decryption failed');
    }
  }
}

/**
 * Encrypts a dotenvx private key using Windows DPAPI
 * This is used by the encrypt command to create DPAPI-encrypted keys
 * @deprecated Use DPAPIProvider.encrypt() instead
 */
export function encryptKeyWithDPAPI(privateKey: string): string {
  const provider = new DPAPIProvider();
  return provider.encrypt(privateKey);
}

/**
 * Check if DPAPI is available (Windows only)
 */
export function isDPAPIAvailable(): boolean {
  return platform() === 'win32';
}

