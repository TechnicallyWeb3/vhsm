# Provider Development Guide

This directory contains key decryption providers for vhsm. Providers implement the `KeyDecryptionProvider` interface to support different key management backends.

## Provider Interface

All providers must implement:

```typescript
interface KeyDecryptionProvider {
  readonly name: string;
  readonly requiresInteraction: boolean;
  decrypt(encryptedKey: string): Promise<string>;
}
```

## Available Providers

### `password` (Default)

Password-based encryption using AES-256-GCM. Prompts user for passphrase at runtime.

**Status**: ✅ Implemented

## Planned Providers

### `docker-secrets`

Reads decryption secret from Docker secrets mount point.

**Implementation Notes**:
- Read secret from `/run/secrets/dotenvx-key` or configurable path
- Use secret to decrypt the encrypted key
- No user interaction required

### `windows-dpapi`

Uses Windows Data Protection API (DPAPI) for key protection.

**Implementation Notes**:
- Use `System.Security.Cryptography.ProtectedData` via PowerShell
- Scope: `CurrentUser` (user-specific encryption)
- No user interaction required (uses Windows user context)

### `keychain` (macOS)

Stores and retrieves decryption secret from macOS Keychain.

**Implementation Notes**:
- Use `security` command-line tool
- Store secret in Keychain with service name `vhsm`
- Retrieve on demand for decryption
- No user interaction required (uses Keychain authentication)

### `tpm`

Uses Trusted Platform Module (TPM) for key unwrapping.

**Implementation Notes**:
- Use TPM2 tools or library
- Unwrap key using TPM-sealed key
- Requires TPM hardware and proper setup
- No user interaction required

### `hsm`

Hardware Security Module integration via PKCS#11.

**Implementation Notes**:
- Use PKCS#11 library (e.g., `pkcs11`)
- Connect to HSM device
- Use HSM key for decryption
- Requires HSM hardware and configuration
- No user interaction required

## Creating a New Provider

1. Create a new file in this directory: `src/providers/your-provider.ts`

2. Implement the interface:

```typescript
import type { KeyDecryptionProvider } from '../types.js';
import { DecryptionError } from '../types.js';

export class YourProvider implements KeyDecryptionProvider {
  readonly name = 'your-provider';
  readonly requiresInteraction = false; // or true if user input needed

  async decrypt(encryptedKey: string): Promise<string> {
    try {
      // Your decryption logic
      return decryptedKey;
    } catch (error) {
      throw new DecryptionError('Failed to decrypt key');
    }
  }
}
```

3. Register in `src/providers/index.ts`:

```typescript
import { YourProvider } from './your-provider.js';
providers.set('your-provider', new YourProvider());
```

4. Update documentation in main README.md

## Security Considerations

- Never log or expose decrypted keys
- Use secure defaults for all cryptographic operations
- Handle errors gracefully without leaking information
- Clear sensitive data from memory when possible
- Validate all inputs before processing
- Use well-maintained cryptographic libraries

## Testing Providers

Test your provider with:

```bash
# Encrypt a test key
vhsm encrypt .env.keys -o test.keys.encrypted

# Test decryption
vhsm run -p your-provider -k test.key.encrypted echo "Success"
```

Ensure:
- Decryption works correctly
- Errors are handled securely
- No secrets leak in error messages
- Provider works in different environments

