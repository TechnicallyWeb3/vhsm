import type { KeyDecryptionProvider } from '../types.js';
import { PasswordProvider } from './password.js';

/**
 * Registry of available key decryption providers
 */
const providers = new Map<string, KeyDecryptionProvider>();

// Register default provider
providers.set('password', new PasswordProvider());

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

