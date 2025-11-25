/**
 * Virtual HSM - Secure dotenvx wrapper
 * 
 * Main entry point for programmatic usage
 */

export { getProvider, registerProvider, listProviders, getDefaultProvider } from './providers/index.js';
export { PasswordProvider, encryptKeyWithPassword } from './providers/password.js';
export { DPAPIProvider, encryptKeyWithDPAPI, isDPAPIAvailable } from './providers/dpapi.js';
export { FIDO2Provider, encryptKeyWithFIDO2, isFIDO2Available } from './providers/fido2.js';
export { SessionCache } from './cache.js';
export { createKeyId, sanitizeError, clearString } from './security.js';
export { loadConfig } from './config.js';
export type { KeyDecryptionProvider, VhsmConfig, CachedKey, DecryptionError } from './types.js';

