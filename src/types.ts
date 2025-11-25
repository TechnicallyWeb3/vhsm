/**
 * Pluggable key decryption provider interface
 */
export interface KeyDecryptionProvider {
  /**
   * Decrypts the encrypted private key using the provider's method
   * @param encryptedKey - The encrypted private key (base64 or hex encoded)
   * @returns The decrypted private key as a string
   * @throws {DecryptionError} if decryption fails
   */
  decrypt(encryptedKey: string): Promise<string>;
  
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
  providerConfig?: Record<string, unknown>;
}

/**
 * Cached key entry
 */
export interface CachedKey {
  key: string;
  timestamp: number;
  expiresAt: number;
}

