/**
 * Provider-specific configuration options
 */
export interface ProviderConfig {
  /**
   * Password/passphrase for password-based providers
   */
  password?: string;
  
  /**
   * Credential ID for FIDO2 provider
   */
  credentialId?: string;
  
  /**
   * Authorization password for TPM2 provider
   */
  authPassword?: string;
  
  /**
   * Additional provider-specific options
   */
  [key: string]: unknown;
}

/**
 * Unified provider interface for encryption and decryption
 */
export interface Provider {
  /**
   * Provider name for identification and configuration
   */
  readonly name: string;
  
  /**
   * Whether this provider requires user interaction
   */
  readonly requiresInteraction: boolean;
  
  /**
   * Encrypts a plaintext key using the provider's method
   * @param plaintextKey - The plaintext key to encrypt
   * @param config - Provider-specific configuration options
   * @returns The encrypted key as a string (format: provider-specific)
   * @throws {Error} if encryption fails
   */
  encrypt(plaintextKey: string, config?: ProviderConfig): Promise<string> | string;
  
  /**
   * Decrypts the encrypted private key using the provider's method
   * @param encryptedKey - The encrypted private key (base64 or hex encoded)
   * @param config - Provider-specific configuration options
   * @returns The decrypted private key as a string
   * @throws {DecryptionError} if decryption fails
   */
  decrypt(encryptedKey: string, config?: ProviderConfig): Promise<string>;
  
  /**
   * Validates provider configuration before encryption
   * Used to ensure encryption will succeed before running dotenvx
   * @param config - Provider-specific configuration options
   * @param existingKeys - Existing encrypted keys (for validation)
   * @returns Validation result with any validated credentials/values
   */
  validateEncryption?(config?: ProviderConfig, existingKeys?: Array<{ provider: string; encryptedValue: string }>): Promise<ProviderConfig | void>;
}

/**
 * @deprecated Use Provider instead
 * Pluggable key decryption provider interface (legacy)
 */
export interface KeyDecryptionProvider {
  /**
   * Decrypts the encrypted private key using the provider's method
   * @param encryptedKey - The encrypted private key (base64 or hex encoded)
   * @returns The decrypted private key as a string
   * @throws {DecryptionError} if decryption fails
   */
  decrypt(encryptedKey: string, providedPassword?: string): Promise<string>;
  
  /**
   * Provider name for identification and configuration
   */
  readonly name: string;
  
  /**
   * Whether this provider requires user interaction
   */
  readonly requiresInteraction: boolean;
}

/**
 * Custom error class for decryption failures
 * Ensures no secret leakage in error messages
 */
export class DecryptionError extends Error {
  constructor(message: string = 'Decryption failed') {
    super(message);
    this.name = 'DecryptionError';
    Object.setPrototypeOf(this, DecryptionError.prototype);
  }
}

/**
 * Configuration for vhsm
 */
export interface VhsmConfig {
  /**
   * Provider to use for key decryption
   * Default: 'password'
   */
  provider?: string;
  
  /**
   * Session cache timeout in milliseconds
   * Default: 3600000 (1 hour)
   */
  cacheTimeout?: number;
  
  /**
   * Whether to enable session caching
   * Default: true
   */
  enableCache?: boolean;
  
  /**
   * Provider-specific configuration
   */
  providerConfig?: ProviderConfig;
  
  /**
   * Whether to allow exec() function execution
   * This is a security feature - exec() will throw an error if not explicitly enabled
   * Default: false (must be explicitly enabled)
   */
  allowExec?: boolean;
}

/**
 * Cached key entry
 */
export interface CachedKey {
  key: string;
  timestamp: number;
  expiresAt: number;
}

