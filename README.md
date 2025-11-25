# vhsm - Virtual HSM

**Virtual HSM** is a secure wrapper for [dotenvx](https://github.com/dotenvx/dotenvx) that provides pluggable key decryption mechanisms for local development environments. It ensures that dotenvx private keys are never stored in plaintext and are only decrypted in memory at runtime.

## Features

- 🔐 **Secure Key Decryption**: Prompts for passphrase at runtime to decrypt dotenvx private keys
- 💾 **In-Memory Only**: Decrypted keys never touch disk or logs
- 🔌 **Pluggable Architecture**: Extensible provider system for different key management backends
- ⏱️ **Session Caching**: Optional in-memory cache with timeout to reduce repeated prompts
- 🛡️ **Secure Defaults**: Built-in best practices for cryptographic key handling
- 🚫 **No Secret Leakage**: Error handling sanitizes messages to prevent information disclosure
- 🔧 **Developer-Friendly**: Simple CLI workflow that integrates seamlessly with dotenvx

## Installation

```bash
npm install -g vhsm
# or
npm install --save-dev vhsm
```

**Prerequisites**: You must have `@dotenvx/dotenvx` installed and available in your PATH.

## Quick Start

### 1. Encrypt Your dotenvx Private Key

Encrypt your dotenvx private key (automatically runs `dotenvx encrypt` first if needed):

```bash
vhsm encrypt
# or with custom options
vhsm encrypt -fk .env.keys -o .env.keys.encrypted
```

This will:
- Run `dotenvx encrypt` to generate/update `.env.keys` from your `.env` files
- Prompt you for a passphrase (minimum 8 characters)
- Encrypt the key using AES-256-GCM
- Save it as `VHSM_PRIVATE_KEY=encrypted:...` to `.env.keys.encrypted` with secure file permissions (600)
- Delete the original `.env.keys` file (use `--no-delete` to keep it)

### 2. Use vhsm to Run Commands

Instead of using `dotenvx run` directly, use `vhsm run`:

```bash
vhsm run npm start
# or
vhsm run -- node server.js
# or with custom encrypted key file
vhsm run -ef custom/path/.env.keys.encrypted -- npm start
```

vhsm will:
1. Prompt you for the passphrase to decrypt the key
2. Decrypt the key in memory
3. Inject it as `DOTENV_PRIVATE_KEY` environment variable
4. Execute `dotenvx run` with your command

### 3. Session Caching (Optional)

By default, vhsm caches decrypted keys in memory for 1 hour to avoid repeated prompts:

```bash
# Disable caching
vhsm run --no-cache npm start

# Custom cache timeout (in milliseconds)
vhsm run --cache-timeout 1800000 npm start  # 30 minutes
```

Clear the cache manually:
```bash
vhsm clear-cache
```

## Configuration

### Configuration File

Create a `.vhsmrc.json` or `.vhsm.json` file in your project root:

```json
{
  "provider": "password",
  "cacheTimeout": 3600000,
  "enableCache": true,
  "providerConfig": {}
}
```

Configuration is also supported via environment variables:
- `VHSM_PROVIDER`: Provider name (default: `password`)
- `VHSM_CACHE_TIMEOUT`: Cache timeout in milliseconds (default: `3600000`)
- `VHSM_ENABLE_CACHE`: Enable/disable caching (default: `true`)

### Command-Line Options

#### `vhsm run`

```bash
vhsm run [options] <command...>

Options:
  -ef, --encrypted-key <path>  Path to encrypted private key file (default: .env.keys.encrypted)
  -p, --provider <name>        Key decryption provider to use (default: password)
  -pw, --password <pass>       Password/passphrase for decryption (for testing)
  -nc, --no-cache              Disable session caching
  -ct, --cache-timeout <ms>     Cache timeout in milliseconds (default: 3600000)
```

#### `vhsm encrypt`

```bash
vhsm encrypt [options]

Options:
  -o, --output <path>          Output path for encrypted key (default: .env.keys.encrypted)
  -pw, --password <pass>        Password/passphrase for encryption (for testing)
  -nd, --no-delete              Do not delete the original .env.keys file after encryption
  -fk, --env-keys-file <path>   Path to plaintext private key file (default: .env.keys)
  
  # Pass-through options for dotenvx encrypt:
  -f, --env-file <paths...>     Path(s) to your env file(s)
  -k, --key <keys...>           Key(s) to encrypt (default: all keys in file)
  -ek, --exclude-key <keys...>  Key(s) to exclude from encryption (default: none)
```

#### `vhsm decrypt`

```bash
vhsm decrypt [options]

Options:
  -ef, --encrypted-key <path>   Path to encrypted private key file (default: .env.keys.encrypted)
  -p, --provider <name>           Key decryption provider to use (default: password)
  -pw, --password <pass>         Password/passphrase for decryption (for testing)
  -nc, --no-cache                Disable session caching
  -ct, --cache-timeout <ms>      Cache timeout in milliseconds (default: 3600000)
  -r, --restore                  Restore the decrypted key to a .env.keys file
  -fk, --env-keys-file <path>    Output path for restored key file (used with --restore) (default: .env.keys)
  
  # Pass-through options for dotenvx decrypt:
  -f, --env-file <paths...>      Path(s) to your env file(s)
  -k, --key <keys...>            Key(s) to decrypt (default: all keys in file)
  -ek, --exclude-key <keys...>   Key(s) to exclude from decryption (default: none)
```

## Security Best Practices

### Key Storage

1. **Never commit encrypted keys to version control**
   - Add `.env.keys.encrypted` to your `.gitignore`
   - Use secure secret management for team sharing

2. **Secure file permissions**
   - Encrypted key files are created with mode `600` (owner read/write only)
   - Verify permissions: `chmod 600 .env.keys.encrypted`

3. **Strong passphrases**
   - Use a strong, unique passphrase (minimum 12+ characters recommended)
   - Consider using a password manager
   - Never reuse passphrases from other systems

4. **Environment isolation**
   - Use different encrypted keys for different environments
   - Rotate keys periodically

### Memory Safety

- Decrypted keys exist only in process memory
- Keys are cleared from memory after spawning dotenvx (best effort)
- Session cache is in-memory only and expires automatically
- No keys are written to disk or logs

### Error Handling

- Error messages are sanitized to prevent secret leakage
- Stack traces are limited to prevent information disclosure
- Failed decryption attempts don't reveal key structure

## Architecture

### Provider System

vhsm uses a pluggable provider architecture for key decryption. The default `password` provider uses AES-256-GCM encryption with PBKDF2 key derivation.

#### Creating Custom Providers

Implement the `KeyDecryptionProvider` interface:

```typescript
import type { KeyDecryptionProvider } from 'vhsm';

export class MyCustomProvider implements KeyDecryptionProvider {
  readonly name = 'my-provider';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    // Your decryption logic here
    return decryptedKey;
  }
}
```

Register your provider:

```typescript
import { registerProvider } from 'vhsm';
import { MyCustomProvider } from './my-provider.js';

registerProvider(new MyCustomProvider());
```

## Future Provider Integrations

The architecture is designed to support various key management backends:

### Docker Secrets

```typescript
export class DockerSecretsProvider implements KeyDecryptionProvider {
  readonly name = 'docker-secrets';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    const secretPath = process.env.DOCKER_SECRET_PATH || '/run/secrets/dotenvx-key';
    const secret = await readFile(secretPath, 'utf-8');
    // Decrypt using secret
    return decrypt(encryptedKey, secret);
  }
}
```

### Windows DPAPI

```typescript
import { execSync } from 'child_process';

export class WindowsDPAPIProvider implements KeyDecryptionProvider {
  readonly name = 'windows-dpapi';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    // Use PowerShell to decrypt with DPAPI
    const script = `[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String('${encryptedKey}'), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))`;
    return execSync(`powershell -Command "${script}"`, { encoding: 'utf-8' }).trim();
  }
}
```

### macOS Keychain

```typescript
import { execSync } from 'child_process';

export class KeychainProvider implements KeyDecryptionProvider {
  readonly name = 'keychain';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    // Use security command to retrieve from Keychain
    const service = 'vhsm';
    const account = 'dotenvx-key';
    const password = execSync(
      `security find-generic-password -s ${service} -a ${account} -w`,
      { encoding: 'utf-8' }
    ).trim();
    return decrypt(encryptedKey, password);
  }
}
```

### TPM (Trusted Platform Module)

```typescript
import { Tpm2Tools } from 'tpm2-tools';

export class TPMProvider implements KeyDecryptionProvider {
  readonly name = 'tpm';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    // Use TPM to unwrap the key
    const tpm = new Tpm2Tools();
    const handle = process.env.TPM_KEY_HANDLE || '0x81000000';
    return await tpm.unseal(encryptedKey, handle);
  }
}
```

### Hardware HSM

```typescript
import { PKCS11 } from 'pkcs11';

export class HSMProvider implements KeyDecryptionProvider {
  readonly name = 'hsm';
  readonly requiresInteraction = false;

  async decrypt(encryptedKey: string): Promise<string> {
    const session = await PKCS11.openSession({
      library: process.env.PKCS11_LIB,
      slot: parseInt(process.env.PKCS11_SLOT || '0'),
      pin: process.env.PKCS11_PIN,
    });
    
    const key = await session.getKey(process.env.HSM_KEY_ID);
    return await key.decrypt(encryptedKey);
  }
}
```

## API Reference

### Programmatic Usage

```typescript
import { getProvider, SessionCache, createKeyId } from 'vhsm';

// Get a provider
const provider = getProvider('password');

// Decrypt a key
const decrypted = await provider.decrypt(encryptedKey);

// Use session cache
const cache = new SessionCache(3600000); // 1 hour timeout
const keyId = createKeyId(encryptedKey);
cache.set(keyId, decrypted);
const cached = cache.get(keyId);
```

## Test Application

A complete test application is included in the `test-app/` directory to demonstrate the vhsm workflow.

### Quick Demo

**Windows (PowerShell):**
```powershell
.\test-app\demo-flow.ps1
```

**Linux/Mac:**
```bash
bash test-app/demo-flow.sh
```

### Manual Setup

```bash
# 1. Install test app dependencies
cd test-app
npm install

# 2. Create .env file
node create-env.js

# 3. Generate dotenvx key
dotenvx encrypt

# 4. Encrypt the key (from project root)
cd ..
node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted

# 5. Run the test server
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js
```

### Verify Setup

```bash
cd test-app
node verify-setup.js
```

See `test-app/README.md` and `test-app/QUICKSTART.md` for detailed instructions.

## Troubleshooting

### "Failed to read encrypted key file"

- Ensure the encrypted key file exists at the specified path
- Check file permissions (should be readable by current user)
- Verify the path is correct (use `-k` option to specify custom path)

### "Decryption failed"

- Verify you're using the correct passphrase
- Ensure the encrypted key file wasn't corrupted
- Try re-encrypting the key: `vhsm encrypt .env.keys -o .env.keys.encrypted`

### "dotenvx: command not found"

- Install `@dotenvx/dotenvx`: `npm install -g @dotenvx/dotenvx`
- Ensure `dotenvx` is in your PATH

### Cache not working

- Check that caching is enabled: `vhsm run --cache-timeout 3600000`
- Verify the key ID hasn't changed (different encrypted keys = different cache entries)
- Clear cache and retry: `vhsm clear-cache`

## Contributing

Contributions are welcome! Areas for improvement:

- Additional provider implementations (Docker, DPAPI, Keychain, TPM, HSM)
- Enhanced error messages (while maintaining security)
- Performance optimizations
- Additional security features

## License

MIT

## Acknowledgments

- Built for use with [dotenvx](https://github.com/dotenvx/dotenvx)
- Inspired by best practices from HSM and key management systems

