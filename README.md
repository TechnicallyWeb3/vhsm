# vhsm - Virtual HSM

**Virtual HSM** is a secure wrapper for [dotenvx](https://github.com/dotenvx/dotenvx) that provides pluggable key decryption mechanisms for local development environments. It ensures that dotenvx private keys are never stored in plaintext and are only decrypted in memory at runtime.

## Features

- 🔐 **Secure Key Decryption**: Password (AES-256-GCM), Windows DPAPI, FIDO2, and TPM2 providers built-in
- 💾 **In-Memory Only**: Decrypted keys never touch disk or logs
- 🔌 **Pluggable Architecture**: Easily extend with your own provider
- ⏱️ **Session Caching**: Optional in-memory cache with timeout to reduce repeated prompts
- 🛡️ **Secure Defaults**: Built-in best practices for cryptographic key handling
- 🪟 **Native Windows Support**: DPAPI ties secrets to the signed-in Windows user
- 🔑 **Hardware Backed Security**: FIDO2 (Windows Hello, security keys, mobile keys) and TPM2 with beautiful, guided UI
- 🚫 **No Secret Leakage**: Error handling sanitizes messages to prevent information disclosure
- 🔧 **Developer-Friendly**: Simple CLI workflow that integrates seamlessly with dotenvx
- ⚡ **Programmatic Execution**: `vhsm.exec()` allows secure function execution with automatic env variable injection

## Installation

```bash
npm install -g vhsm
# or
npm install --save-dev vhsm
```

**Prerequisites**: None! vhsm includes `@dotenvx/dotenvx` as a dependency, so no separate installation is needed.

## Quick Start

### 1. Encrypt Your dotenvx Private Key

Run `vhsm encrypt` from your project root. Choose a provider:

| Scenario | Command |
| --- | --- |
| Cross-platform / CI friendly | `vhsm encrypt` (password) |
| Windows workstation | `vhsm encrypt -p dpapi` |
| Hardware-backed (FIDO2) | `vhsm encrypt -p fido2` |
| Hardware-backed (TPM2) | `vhsm encrypt -p tpm2` |

Each provider automatically runs `dotenvx encrypt` first, then:

- **password**: prompts for an 8+ char passphrase and stores `encrypted:...`
- **dpapi**: no password prompts; Windows ties data to the signed-in user
- **fido2**: opens a local browser page for authentication (Windows Hello, security keys, mobile keys, etc.)
- **tpm2**: uses TPM 2.0 hardware chip (Linux/macOS only, or Docker on Windows)

Output is written to `.env.keys.encrypted` (600 perms). Remove plaintext `.env.keys` unless `--no-delete`.

### 2. Use vhsm to Run Commands

Instead of using `dotenvx run` directly, use `vhsm run`:

```bash
vhsm run -- npm start
# or
vhsm run -- node server.js
# or with custom encrypted key file
vhsm run -ef custom/path/.env.keys.encrypted -- npm start
```

**Note**: Always use `--` to separate vhsm options from your command.

vhsm will:
1. Automatically detect the provider from the encrypted key file (password, dpapi, fido2, or tpm2)
2. Prompt for authentication if needed (passphrase, FIDO2 touch, etc.)
3. Decrypt the key in memory
4. Inject it as `DOTENV_PRIVATE_KEY` environment variable
5. Execute `dotenvx run` with your command

### 3. Session Caching (Optional)

By default, vhsm caches decrypted keys in memory for 1 hour to avoid repeated prompts:

```bash
# Disable caching
vhsm run --no-cache -- npm start

# Custom cache timeout (in milliseconds)
vhsm run --cache-timeout 1800000 -- npm start  # 30 minutes
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
  "allowExec": false,
  "providerConfig": {}
}
```

- Set `"provider": "dpapi"` on Windows to default to DPAPI.
- Set `"provider": "fido2"` if you always want the FIDO2 flow.

Environment variable overrides:
- `VHSM_PROVIDER`: `password`, `dpapi`, or `fido2`
- `VHSM_CACHE_TIMEOUT`: Milliseconds (default `3600000`)
- `VHSM_ENABLE_CACHE`: `true` / `false`
- `VHSM_ALLOW_EXEC`: `true` / `false` - Enable `vhsm.exec()` function (default: `false` for security)

### Command-Line Options

#### `vhsm run`

```bash
vhsm run [options] <command...>

Options:
  -ef, --encrypted-key <path>  Path to encrypted private key file (default: .env.keys.encrypted)
  -pw, --password <pass>       Password/passphrase for decryption (for testing, password/tpm2 providers only)
  -nc, --no-cache              Disable session caching
  -ct, --cache-timeout <ms>     Cache timeout in milliseconds (default: 3600000)
  
Note: Provider is automatically detected from the encrypted key file. No need to specify `-p`.
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
  -pw, --password <pass>         Password/passphrase for decryption (for testing, password/tpm2 providers only)
  -nc, --no-cache                Disable session caching
  -ct, --cache-timeout <ms>      Cache timeout in milliseconds (default: 3600000)
  -r, --restore                  Restore the decrypted key to a .env.keys file
  -fk, --env-keys-file <path>    Output path for restored key file (used with --restore) (default: .env.keys)
  
Note: Provider is automatically detected from the encrypted key file. No need to specify `-p`.
  
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

## Providers

| Provider | Platforms | Interaction | Best For |
| --- | --- | --- | --- |
| `password` (default) | All | Passphrase prompt | Portability, CI, team sharing |
| `dpapi` | Windows 10/11+ | None | Individual Windows workstations |
| `fido2` | All | FIDO2 authentication (Windows Hello, security keys, mobile) | Hardware-backed secrets |
| `tpm2` | Linux/macOS | Optional PIN | Hardware TPM chip protection |

👉 See `FIDO2-QUICKSTART.md` or `FIDO2-GUIDE.md` for screenshots, troubleshooting, and architecture details.

### Windows DPAPI

- Encrypt: `vhsm encrypt -p dpapi`
- Run: `vhsm run -- npm start` (auto-detects provider)
- Keys can only be decrypted by the same Windows user profile.
- Great for local dev; not suitable for CI or shared servers.

### FIDO2 (Windows Hello, Security Keys, Mobile Keys)

- Encrypt: `vhsm encrypt -p fido2`
- Run: `vhsm run -- npm start` (auto-detects provider)
- Browser flow opens automatically (`http://localhost:8765`) with polished UI.
- Supports Windows Hello (PIN/biometric), hardware security keys (YubiKey, etc.), and mobile keys (Face ID via QR code).
- One credential protects multiple env files; authenticate once per session to decrypt.
- Works cross-platform as long as a browser + FIDO2 authenticator is present.

### TPM2 (Trusted Platform Module)

- Encrypt: `vhsm encrypt -p tpm2`
- Run: `vhsm run -- npm start` (auto-detects provider)
- Uses TPM 2.0 hardware chip for hardware-backed encryption.
- Optional authorization password for additional security layer.
- Linux/macOS only (or use Docker on Windows - see `test-app/DOCKER.md`).

## Architecture

### Provider System

vhsm uses a pluggable provider architecture. The built-in providers satisfy most workflows, but you can register custom ones.

## Additional Guides

- [`QUICKSTART.md`](./QUICKSTART.md) – Get started quickly with password or FIDO2 providers.
- [`FIDO2-QUICKSTART.md`](./FIDO2-QUICKSTART.md) – FIDO2 test flow, screenshots, troubleshooting.
- [`FIDO2-GUIDE.md`](./FIDO2-GUIDE.md) – Deep dive into FIDO2 security model, remote access tips, FAQs.
- [`EXEC-FEATURE.md`](./EXEC-FEATURE.md) – Complete guide to `vhsm.exec()` programmatic function execution.
- [`PUBLISHING.md`](./PUBLISHING.md) – Instructions for shipping vhsm to npm.

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

#### Provider API

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

#### Secure Function Execution (`vhsm.exec()`)

`vhsm.exec()` allows you to execute functions with automatic decryption and injection of environment variables. **This feature is disabled by default for security** - you must explicitly enable it.

**Enable exec():**

1. Environment variable: `export VHSM_ALLOW_EXEC=true`
2. Config file: Add `"allowExec": true` to `.vhsmrc.json`
3. Per-execution: Pass `allowExec: true` in options

**Basic Example:**

```typescript
import { exec } from 'vhsm';

// Enable exec() first (one of the methods above)
const result = await exec(
  async ({ message, apiKey }) => {
    // apiKey is automatically decrypted from @vhsm API_KEY
    return signMessage(message, apiKey);
  },
  {
    message: 'Hello, World!',
    apiKey: '@vhsm API_KEY'  // Automatically decrypted from .env
  },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    envFile: '.env',
    allowExec: true  // Required if not set globally
  }
);
```

**Nested Execution:**

```typescript
// exec() calls can be nested - useful for loading wallets, signing transactions, etc.
const result = await exec(
  async ({ wallet }) => {
    // wallet is loaded via nested exec()
    return wallet.signTransaction(tx);
  },
  {
    wallet: await exec(
      loadWallet,
      { mnemonic: '@vhsm CRYPTO_WALLET' },
      { allowExec: true }
    )
  },
  { allowExec: true }
);
```

**Features:**
- ✅ Automatic env variable decryption and injection
- ✅ Memory cleanup of sensitive data after execution
- ✅ Nested/recursive execution support
- ✅ Session caching support
- ✅ Security gate (disabled by default)

👉 See [`EXEC-FEATURE.md`](./EXEC-FEATURE.md) for complete documentation and examples.

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
node dist/cli.js run -ef test-app/.env.keys.encrypted -- node test-app/server.js
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

This shouldn't happen as vhsm includes dotenvx as a dependency. If you see this error:
- Reinstall vhsm: `npm install -g vhsm`
- Check that vhsm's dependencies installed correctly

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

