import type { Provider, KeyDecryptionProvider, ProviderConfig } from '../types.js';
/**
 * Password-based key decryption provider
 * Uses AES-256-GCM for encryption/decryption
 * Supports Argon2id (default) and SHA256 (legacy) key derivation
 */
export declare class PasswordProvider implements Provider, KeyDecryptionProvider {
    readonly name = "password";
    readonly requiresInteraction = true;
    /**
     * Encrypts a plaintext key using password-based encryption
     */
    encrypt(plaintextKey: string, config?: ProviderConfig): Promise<string>;
    /**
     * Validates password before encryption
     */
    validateEncryption(config?: ProviderConfig, existingKeys?: Array<{
        provider: string;
        encryptedValue: string;
    }>): Promise<ProviderConfig | void>;
    /**
     * Decrypts the encrypted key using a password prompt or provided password
     * Supports both legacy interface (string password) and new interface (ProviderConfig)
     */
    decrypt(encryptedKey: string, configOrPassword?: ProviderConfig | string): Promise<string>;
}
/**
 * Utility function to encrypt a key with a password
 * This is useful for initial setup
 * Uses Argon2id by default for secure key derivation
 */
export declare function encryptKeyWithPassword(plaintextKey: string, password: string, kdfVersion?: string): Promise<string>;
//# sourceMappingURL=password.d.ts.map