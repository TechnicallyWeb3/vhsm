import { execSync } from 'node:child_process';
import { platform } from 'node:os';
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Provider, KeyDecryptionProvider, ProviderConfig, PasswordMode } from '../types.js';
import { DecryptionError } from '../types.js';

/**
 * TPM 2.0 key decryption provider
 * Uses Trusted Platform Module for hardware-backed encryption
 * Requires user authentication (PIN/password) for each decryption
 * 
 * Prerequisites:
 * - TPM 2.0 hardware chip (most modern computers have this)
 * - tpm2-tools installed (Linux: sudo apt install tpm2-tools, macOS: brew install tpm2-tools)
 * 
 * Note: tpm2-tools is Linux/macOS only. For Windows testing, use Docker with a Linux container.
 */
export class TPM2Provider implements Provider, KeyDecryptionProvider {
  readonly name = 'tpm2';
  readonly requiresInteraction = true; // Requires PIN/auth on decrypt
  readonly passwordMode: PasswordMode = 'optional';
  readonly outputPrefix = 'tpm2';

  private tpmDir: string;

  constructor() {
    // Verify TPM2 tools are available
    if (!this.isTPM2Available()) {
      throw new Error(
        'TPM2 tools not found. Install tpm2-tools:\n' +
        '  Linux: sudo apt install tpm2-tools\n' +
        '  macOS: brew install tpm2-tools (requires virtual TPM)\n' +
        '  Windows: Use Docker with Linux container (see test-app/DOCKER.md)'
      );
    }

    // Create TPM working directory
    this.tpmDir = join(tmpdir(), 'vhsm-tpm2');
    if (!existsSync(this.tpmDir)) {
      mkdirSync(this.tpmDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Check if TPM2 tools are available
   */
  private isTPM2Available(): boolean {
    try {
      execSync('tpm2_getrandom --help', {
        stdio: 'ignore',
        timeout: 5000,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get or create TPM primary key handle
   * This is the parent key that will be used to seal/unseal data
   */
  private getPrimaryKeyHandle(): string {
    const primaryCtxFile = join(this.tpmDir, 'primary.ctx');

    try {
      // Check if primary key context exists
      if (existsSync(primaryCtxFile)) {
        return primaryCtxFile;
      }

      // Create a new primary key in the owner hierarchy
      // Using RSA 2048 for compatibility
      execSync(
        `tpm2_createprimary -C o -g sha256 -G rsa2048 -c "${primaryCtxFile}"`,
        {
          stdio: 'pipe',
          timeout: 30000,
        }
      );

      return primaryCtxFile;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to create TPM primary key: ${error.message}`);
      }
      throw new Error('Failed to create TPM primary key');
    }
  }

  /**
   * Encrypts data using TPM seal operation
   * Sealed data can only be unsealed by the same TPM
   * Returns base64-encoded sealed blob
   */
  encrypt(plaintextKey: string, config?: ProviderConfig): string {
    const authPassword = config?.authPassword as string | undefined;
    try {
      const primaryCtx = this.getPrimaryKeyHandle();
      const dataFile = join(this.tpmDir, `seal-data-${Date.now()}.txt`);
      const sealedFile = join(this.tpmDir, `sealed-${Date.now()}.bin`);
      const pubFile = join(this.tpmDir, `pub-${Date.now()}.bin`);
      const privFile = join(this.tpmDir, `priv-${Date.now()}.bin`);

      try {
        // Write data to temp file
        writeFileSync(dataFile, plaintextKey, { mode: 0o600 });

        // Create sealing object with optional auth
        // The -p option sets the authorization value (password) for the sealed object
        const authArg = authPassword ? `-p "${authPassword.replace(/"/g, '\\"')}"` : '';
        
        execSync(
          `tpm2_create -C "${primaryCtx}" -i "${dataFile}" -u "${pubFile}" -r "${privFile}" -a "fixedtpm|fixedparent|userwithauth" ${authArg}`,
          {
            stdio: 'pipe',
            timeout: 30000,
          }
        );

        // Load the sealed object and get a handle
        const sealedCtx = join(this.tpmDir, `sealed-ctx-${Date.now()}.ctx`);
        execSync(
          `tpm2_load -C "${primaryCtx}" -u "${pubFile}" -r "${privFile}" -c "${sealedCtx}"`,
          {
            stdio: 'pipe',
            timeout: 30000,
          }
        );

        // Read the sealed blob files and combine them
        const pubData = readFileSync(pubFile);
        const privData = readFileSync(privFile);
        
        // Create a JSON structure with both parts
        const sealedBlob = {
          pub: pubData.toString('base64'),
          priv: privData.toString('base64'),
          hasAuth: !!authPassword,
        };

        return Buffer.from(JSON.stringify(sealedBlob)).toString('base64');
      } finally {
        // Cleanup temp files
        [dataFile, sealedFile, pubFile, privFile].forEach(f => {
          try {
            if (existsSync(f)) unlinkSync(f);
          } catch {}
        });
      }
    } catch (error) {
      if (error instanceof Error) {
        throw new DecryptionError(`TPM2 seal failed: ${error.message}`);
      }
      throw new DecryptionError('TPM2 seal failed');
    }
  }

  /**
   * Validates TPM2 before encryption
   */
  async validateEncryption(config?: ProviderConfig): Promise<ProviderConfig | void> {
    const authPassword = config?.authPassword as string | undefined;
    
    // Test encrypt with dummy data
    try {
      this.encrypt('test-validation', { authPassword });
      console.log('✅ TPM2 validated.');
    } catch (error) {
      throw new Error(`TPM2 validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
    
    return config;
  }

  /**
   * Decrypts the sealed data using TPM unseal operation
   * Requires the same TPM that sealed the data
   * May require user authentication depending on how it was sealed
   */
  async decrypt(encryptedKey: string, configOrPassword?: ProviderConfig | string): Promise<string> {
    // Support both old interface (string) and new interface (ProviderConfig)
    const authPassword = typeof configOrPassword === 'string' 
      ? configOrPassword 
      : configOrPassword?.authPassword as string | undefined;
    try {
      const primaryCtx = this.getPrimaryKeyHandle();
      
      // Decode the sealed blob
      const sealedBlob = JSON.parse(Buffer.from(encryptedKey, 'base64').toString('utf-8'));
      
      const pubFile = join(this.tpmDir, `unseal-pub-${Date.now()}.bin`);
      const privFile = join(this.tpmDir, `unseal-priv-${Date.now()}.bin`);
      const sealedCtx = join(this.tpmDir, `unseal-ctx-${Date.now()}.ctx`);
      const outputFile = join(this.tpmDir, `unseal-output-${Date.now()}.txt`);

      try {
        // Write the blob components to files
        writeFileSync(pubFile, Buffer.from(sealedBlob.pub, 'base64'));
        writeFileSync(privFile, Buffer.from(sealedBlob.priv, 'base64'));

        // Load the sealed object
        execSync(
          `tpm2_load -C "${primaryCtx}" -u "${pubFile}" -r "${privFile}" -c "${sealedCtx}"`,
          {
            stdio: 'pipe',
            timeout: 30000,
          }
        );

        // Unseal the data
        // If auth was set during seal, it must be provided during unseal
        const authArg = sealedBlob.hasAuth && authPassword 
          ? `-p "${authPassword.replace(/"/g, '\\"')}"` 
          : '';
        
        // Try to unseal - this may fail if auth is required but not provided
        try {
          execSync(
            `tpm2_unseal -c "${sealedCtx}" ${authArg} -o "${outputFile}"`,
            {
              stdio: 'pipe',
              timeout: 30000,
            }
          );
        } catch (error) {
          if (error instanceof Error && error.message.includes('authorization')) {
            throw new DecryptionError(
              'TPM2 unseal failed: Authorization required. The sealed data requires a password/PIN.'
            );
          }
          throw error;
        }

        // Read the unsealed data
        const decryptedData = readFileSync(outputFile, 'utf-8');
        return decryptedData;
      } finally {
        // Cleanup temp files
        [pubFile, privFile, sealedCtx, outputFile].forEach(f => {
          try {
            if (existsSync(f)) unlinkSync(f);
          } catch {}
        });
      }
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'DecryptionError') {
          throw error;
        }
        if (error.message.includes('authorization')) {
          throw new DecryptionError(
            'TPM2 unseal failed: Invalid authorization or TPM state mismatch'
          );
        }
        throw new DecryptionError(`TPM2 unseal failed: ${error.message}`);
      }
      throw new DecryptionError('TPM2 unseal failed');
    }
  }
}

/**
 * Encrypts a dotenvx private key using TPM2
 * This is used by the encrypt command to create TPM2-sealed keys
 * @deprecated Use TPM2Provider.encrypt() instead
 */
export function encryptKeyWithTPM2(privateKey: string, authPassword?: string): string {
  const provider = new TPM2Provider();
  return provider.encrypt(privateKey, { authPassword });
}

/**
 * Check if TPM2 is available
 */
export function isTPM2Available(): boolean {
  try {
    execSync('tpm2_getrandom --help', {
      stdio: 'ignore',
      timeout: 5000,
    });
    return true;
  } catch {
    return false;
  }
}

