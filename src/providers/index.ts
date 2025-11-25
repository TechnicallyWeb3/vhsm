import { platform } from 'node:os';
import type { KeyDecryptionProvider } from '../types.js';
import { PasswordProvider } from './password.js';
import { DPAPIProvider } from './dpapi.js';
import { TPM2Provider, isTPM2Available } from './tpm2.js';
import { FIDO2Provider, isFIDO2Available } from './fido2.js';

/**
 * Registry of available key decryption providers
 */
const providers = new Map<string, KeyDecryptionProvider>();

// Register default provider
providers.set('password', new PasswordProvider());

// Register DPAPI provider on Windows
if (platform() === 'win32') {
  try {
    providers.set('dpapi', new DPAPIProvider());
  } catch (error) {
    // DPAPI provider will throw if not on Windows, which is expected
    // This is a safety check in case the platform check fails
  }
}

// Register TPM2 provider if available
if (isTPM2Available()) {
  try {
    providers.set('tpm2', new TPM2Provider());
  } catch (error) {
    // TPM2 provider will throw if tpm2-tools are not available
    console.warn('TPM2 tools detected but provider failed to initialize:', error instanceof Error ? error.message : 'Unknown error');
  }
}

// Register FIDO2 provider if available
if (isFIDO2Available()) {
  try {
    providers.set('fido2', new FIDO2Provider());
  } catch (error) {
    console.warn('FIDO2 provider failed to initialize:', error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * Get a provider by name
 */
export function getProvider(name: string): KeyDecryptionProvider {
  const provider = providers.get(name);
  if (!provider) {
    throw new Error(`Unknown provider: ${name}. Available providers: ${Array.from(providers.keys()).join(', ')}`);
  }
  return provider;
}

/**
 * Register a custom provider
 */
export function registerProvider(provider: KeyDecryptionProvider): void {
  providers.set(provider.name, provider);
}

/**
 * List all registered providers
 */
export function listProviders(): string[] {
  return Array.from(providers.keys());
}

/**
 * Get the default provider
 */
export function getDefaultProvider(): KeyDecryptionProvider {
  return providers.get('password')!;
}

