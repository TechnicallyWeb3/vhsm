import type { CachedKey } from './types.js';

/**
 * In-memory session cache for decrypted keys
 * Keys are stored only in memory and expire after a timeout
 */
export class SessionCache {
  private cache = new Map<string, CachedKey>();
  private defaultTimeout: number;

  constructor(defaultTimeout: number = 3600000) {
    // Default: 1 hour
    this.defaultTimeout = defaultTimeout;
  }

  /**
   * Store a decrypted key in the cache
   */
  set(keyId: string, decryptedKey: string, timeout?: number): void {
    const expiresAt = Date.now() + (timeout ?? this.defaultTimeout);
    this.cache.set(keyId, {
      key: decryptedKey,
      timestamp: Date.now(),
      expiresAt,
    });
  }

  /**
   * Retrieve a decrypted key from the cache if it exists and hasn't expired
   */
  get(keyId: string): string | null {
    const entry = this.cache.get(keyId);
    
    if (!entry) {
      return null;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(keyId);
      return null;
    }

    return entry.key;
  }

  /**
   * Remove a key from the cache
   */
  delete(keyId: string): void {
    this.cache.delete(keyId);
  }

  /**
   * Clear all cached keys
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Clean up expired entries
   */
  cleanup(): void {
    const now = Date.now();
    for (const [keyId, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(keyId);
      }
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; entries: Array<{ keyId: string; expiresIn: number }> } {
    const now = Date.now();
    const entries = Array.from(this.cache.entries()).map(([keyId, entry]) => ({
      keyId,
      expiresIn: Math.max(0, entry.expiresAt - now),
    }));

    return {
      size: this.cache.size,
      entries,
    };
  }
}

