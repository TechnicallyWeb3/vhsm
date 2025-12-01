import { platform } from 'node:os';
import type { Provider, KeyDecryptionProvider } from '../types.js';
import { PasswordProvider } from './password.js';
import { DPAPIProvider } from './dpapi.js';
import { TPM2Provider, isTPM2Available } from './tpm2.js';
import { FIDO2Provider, isFIDO2Available } from './fido2.js';
import { loadConfig } from '../config.js';

/**
 * Registry of available providers (unified interface)
 */
const providers = new Map<string, Provider>();

// Register default provider
const passwordProvider = new PasswordProvider();
providers.set('password', passwordProvider);

// Register DPAPI provider on Windows
if (platform() === 'win32') {
  try {
    const dpapiProvider = new DPAPIProvider();
    providers.set('dpapi', dpapiProvider);
  } catch (error) {
    // DPAPI provider will throw if not on Windows, which is expected
    // This is a safety check in case the platform check fails
    throw new Error('DPAPI provider failed to register');
  }
}

// Register TPM2 provider if available
if (isTPM2Available()) {
  try {
    const tpm2Provider = new TPM2Provider();
    providers.set('tpm2', tpm2Provider);
  } catch (error) {
    // TPM2 provider will throw if tpm2-tools are not available
    console.warn('TPM2 tools detected but provider failed to initialize:', error instanceof Error ? error.message : 'Unknown error');
  }
}

// Register FIDO2 provider if available
if (isFIDO2Available()) {
  try {
    const fido2Provider = new FIDO2Provider();
    providers.set('fido2', fido2Provider);
  } catch (error) {
    console.warn('FIDO2 provider failed to initialize:', error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * Get a provider by name (unified interface)
 */
export function getProvider(name: string): Provider {
  const provider = providers.get(name);
  if (!provider) {
    throw new Error(`Unknown provider: ${name}. Available providers: ${Array.from(providers.keys()).join(', ')}`);
  }
  return provider;
}

/**
 * Register a custom provider
 */
export function registerProvider(provider: Provider): void {
  providers.set(provider.name, provider);
}

/**
 * List all registered providers
 */
export function listProviders(): string[] {
  return Array.from(providers.keys());
}

/**
 * Get the default provider (unified interface)
 */
export function getDefaultProvider(): Provider {
  return providers.get(loadConfig().provider || 'password')!;
}
