import { createHash } from 'node:crypto';

/**
 * Security utilities for safe key handling
 */

/**
 * Create a stable key ID from encrypted key content
 * Used for cache lookups without storing the encrypted key
 */
export function createKeyId(encryptedKey: string): string {
  return createHash('sha256').update(encryptedKey).digest('hex').substring(0, 16);
}

/**
 * Sanitize error messages to prevent secret leakage
 */
export function sanitizeError(error: unknown): Error {
  if (error instanceof Error) {
    // Remove any potential secret patterns from error messages
    let message = error.message;
    
    // Remove base64-looking strings that might be keys
    message = message.replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[REDACTED]');
    
    // Remove hex strings that might be keys
    message = message.replace(/[0-9a-fA-F]{32,}/g, '[REDACTED]');
    
    // Create a new error with sanitized message
    const sanitized = new Error(message);
    sanitized.name = error.name;
    sanitized.stack = error.stack?.split('\n').slice(0, 3).join('\n'); // Limit stack trace
    
    return sanitized;
  }
  
  return new Error('An unknown error occurred');
}

/**
 * Clear a string from memory (best effort)
 * Note: JavaScript doesn't guarantee memory clearing, but we try
 */
export function clearString(str: string): void {
  if (typeof str === 'string' && str.length > 0) {
    // Overwrite with null bytes (best effort)
    const arr = str.split('');
    for (let i = 0; i < arr.length; i++) {
      arr[i] = '\0';
    }
  }
}

