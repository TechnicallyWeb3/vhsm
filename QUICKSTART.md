# Quick Start Guide

This guide walks you through getting started with vhsm. Choose the encryption provider that best fits your needs.

## Step 1: Install vhsm

```bash
npm install -g vhsm
```

That's it! vhsm includes everything you need, including dotenvx. No additional setup required.

## Step 2: Choose Your Provider

vhsm supports multiple encryption providers. Choose the one that fits your workflow:

| Provider | Best For | Requirements |
| --- | --- | --- |
| **Password** | Portability, CI/CD, team sharing | None - works everywhere |
| **FIDO2** | Hardware-backed security | Windows Hello, security key, or mobile authenticator |
| **DPAPI** | Windows workstations | Windows 10/11 only |
| **TPM2** | Hardware TPM chip | Linux/macOS (or Docker on Windows) |

This guide covers **Password** and **FIDO2** - the two most common options. See [README.md](./README.md) for other providers.

---

## Option A: Password Provider

The simplest and most portable option. Works everywhere, including CI/CD pipelines.

### Encrypt Your Keys

```bash
vhsm encrypt
```

This will:
1. Automatically run `dotenvx encrypt` to generate `.env.keys` from your `.env` files
2. Prompt you to enter a passphrase (minimum 8 characters)
3. Ask you to confirm the passphrase
4. Encrypt the keys and save to `.env.keys.encrypted`
5. Delete the original `.env.keys` file (for security)

**Example output:**
```
Running dotenvx encrypt...
✔ encrypted (.env)
✔ key added to .env.keys (DOTENV_PRIVATE_KEY)

Enter passphrase to encrypt the key: ********
Confirm passphrase: ********
VHSM encrypted keys written to: .env.keys.encrypted
Make sure to secure this file and never commit it to version control.
Deleted original key file: .env.keys
```

### Run Your Application

```bash
vhsm run -- npm start
```

**Important**: Always use `--` to separate vhsm options from your command.

**First run:**
```
Enter passphrase to decrypt dotenvx private key: ********
[Your app starts...]
```

**Subsequent runs** (within 1 hour):
```
[Your app starts immediately - key is cached]
```

### Decrypt Keys (Optional)

```bash
# View decrypted keys (doesn't save to file)
vhsm decrypt

# Restore keys to .env.keys file
vhsm decrypt --restore
```

---

## Option B: FIDO2 Provider

Hardware-backed security using Windows Hello, security keys, or mobile authenticators.

### What is FIDO2?

FIDO2 is a modern authentication standard that supports:
- **Windows Hello**: PIN, fingerprint, or facial recognition on Windows
- **Hardware Security Keys**: YubiKey, Titan Security Key, etc.
- **Mobile Authenticators**: Face ID, fingerprint via QR code, etc.

### Encrypt Your Keys

```bash
vhsm encrypt -p fido2
```

This will:
1. Automatically run `dotenvx encrypt` to generate `.env.keys` from your `.env` files
2. Open a browser window at `http://localhost:8765`
3. Show a registration page
4. Ask you to authenticate with your FIDO2 device/method
5. Encrypt the keys and save to `.env.keys.encrypted`
6. Delete the original `.env.keys` file

**What you'll see:**

1. **Browser opens** with a registration page
2. **Click "Register"** button
3. **Authenticate** using:
   - Windows Hello (PIN/fingerprint/face)
   - Security key (touch your YubiKey, etc.)
   - Mobile device (scan QR code, use Face ID, etc.)
4. **Browser closes** automatically
5. **Keys encrypted** and saved

**Example output:**
```
Running dotenvx encrypt...
✔ encrypted (.env)
✔ key added to .env.keys (DOTENV_PRIVATE_KEY)

Encrypting keys with FIDO2...
Found 1 key(s) to encrypt.
You will need to authenticate ONCE to register a credential.

🌐 Please open your browser to: http://localhost:8765

✅ All 1 key(s) encrypted with the same FIDO2 credential.
VHSM encrypted keys written to: .env.keys.encrypted
```

### Run Your Application

```bash
vhsm run -- npm start
```

**Important**: Always use `--` to separate vhsm options from your command.

This will:
1. Read `.env.keys.encrypted`
2. Detect it uses the FIDO2 provider (from the `fido2:` prefix)
3. Open a browser window for authentication
4. Ask you to authenticate with your FIDO2 device/method
5. Decrypt the key in memory
6. Run your application with decrypted environment variables

**What you'll see:**

1. **Browser opens** automatically with authentication page
2. **Click "Unlock"** button (or it auto-clicks)
3. **Authenticate** using the same method you used during encryption:
   - Windows Hello
   - Security key touch
   - Mobile device
4. **Browser closes** automatically
5. **Your app starts** with decrypted environment variables

**First run:**
```
🔑 Please authenticate to decrypt...
🌐 Opening browser for authentication...
[Browser opens, you authenticate]
[Your app starts...]
```

**Subsequent runs** (within 1 hour):
```
[Browser opens briefly, you authenticate]
[Your app starts...]
```

### Decrypt Keys (Optional)

```bash
# View decrypted keys (doesn't save to file)
vhsm decrypt

# Restore keys to .env.keys file
vhsm decrypt --restore
```

### Supported FIDO2 Methods

#### Windows Hello
- **PIN**: Enter your Windows PIN
- **Fingerprint**: Use fingerprint reader
- **Face Recognition**: Use Windows Hello face recognition
- **No additional hardware needed** - uses built-in Windows security

#### Hardware Security Keys
- **YubiKey**: Touch the key when it blinks
- **Titan Security Key**: Touch the key
- **Any FIDO2-compatible key**: Works with any WebAuthn-compatible device

#### Mobile Authenticators
- **Face ID**: Scan QR code, use Face ID on your phone
- **Fingerprint**: Scan QR code, use fingerprint
- **Works with**: iPhone, Android phones with biometric authentication

---

## Programmatic Usage with `vhsm.exec()`

vhsm also provides a powerful programmatic API for executing functions with automatic environment variable injection.

**⚠️ Security Note**: `vhsm.exec()` is **disabled by default** for security. You must enable it first:

```bash
export VHSM_ALLOW_EXEC=true
```

Or add to `.vhsmrc.json`:
```json
{
  "allowExec": true
}
```

### Basic Example

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ message, apiKey }) => {
    // apiKey is automatically decrypted from .env
    return signMessage(message, apiKey);
  },
  {
    message: 'Hello, World!',
    apiKey: '@vhsm API_KEY'  // Automatically decrypted
  },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    envFile: '.env',
    password: 'your-passphrase',
  }
);
```

**⚠️ Security Note:** `exec()` must be enabled via environment variable (`VHSM_ALLOW_EXEC=true`) or config file (`.vhsmrc.json`). It cannot be enabled programmatically for security reasons.

### Nested Execution Example

```typescript
import { exec } from 'vhsm';
import { ethers } from 'ethers';

// Load wallet from mnemonic and sign transaction
// (Requires VHSM_ALLOW_EXEC=true environment variable)
const signedTx = await exec(
  async ({ wallet, to, value }) => {
    return wallet.signTransaction({ to, value });
  },
  {
    // Nested exec() - loads wallet first
    wallet: await exec(
      async ({ mnemonic }) => {
        return ethers.Wallet.fromPhrase(mnemonic);
      },
      {
        mnemonic: '@vhsm CRYPTO_WALLET'
      }
    ),
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5',
    value: ethers.parseEther('0.1')
  }
);
```

**Key Features:**
- `@vhsm KEY` syntax automatically decrypts env variables
- Nested execution for complex workflows
- Automatic memory cleanup of sensitive data
- Session caching support

👉 See [`EXEC-FEATURE.md`](./EXEC-FEATURE.md) for complete documentation.

---

## Complete Examples

### Password Provider

```bash
# 1. Install
npm install -g vhsm

# 2. Encrypt
vhsm encrypt
# Enter passphrase when prompted

# 3. Run your app
vhsm run -- npm start
# Enter passphrase when prompted (first time only)

# 4. Run again (cached - no prompt)
vhsm run -- npm start

# 5. Restore keys if needed
vhsm decrypt --restore
```

### FIDO2 Provider

```bash
# 1. Install
npm install -g vhsm

# 2. Encrypt with FIDO2
vhsm encrypt -p fido2
# Browser opens → Authenticate → Keys encrypted

# 3. Run your app
vhsm run -- npm start
# Browser opens → Authenticate → App runs

# 4. Run again (cached - still need to authenticate)
vhsm run -- npm start
# Browser opens → Authenticate → App runs

# 5. Restore keys if needed
vhsm decrypt --restore
# Browser opens → Authenticate → Keys restored
```

---

## Tips & Best Practices

### General Tips

- **Provider auto-detection**: When using `vhsm run` or `vhsm decrypt`, the provider is automatically detected from the encrypted key file. No need to specify `-p`.
- **Session caching**: Keys are cached in memory for 1 hour by default. Use `vhsm clear-cache` to force re-authentication.
- **Multiple environments**: You can encrypt different keys for different environments:
  ```bash
  vhsm encrypt -f .env.production
  vhsm encrypt -f .env.staging
  ```
- **Custom paths**: Specify custom file locations:
  ```bash
  vhsm encrypt -fk .env.keys -o .secrets/keys.encrypted
  vhsm run -ef .secrets/keys.encrypted -- npm start
  ```

### Password Provider Tips

- **Remember your passphrase**: Without it, you cannot decrypt your keys. Consider using a password manager.
- **Strong passphrases**: Use a strong, unique passphrase (minimum 12+ characters recommended).
- **CI/CD friendly**: Password provider works great in automated environments where you can pass the password via environment variable.

### FIDO2 Provider Tips

- **One credential for all keys**: When encrypting multiple keys, you only need to authenticate once. The same credential is reused.
- **Browser requirements**: FIDO2 requires a modern browser (Chrome, Edge, Firefox, Safari).
- **Localhost only**: The browser page only works on `localhost:8765` for security.
- **Cross-machine**: FIDO2 credentials are tied to the authenticator, not the machine. You can use the same authenticator on different machines, but you need the SAME authenticator that was used for encryption.

---

## Troubleshooting

### "dotenvx: command not found"

This shouldn't happen as vhsm includes dotenvx. If you see this error:
- Reinstall vhsm: `npm install -g vhsm`
- Check that vhsm's dependencies installed correctly

### "Failed to read encrypted key file"

- Ensure the encrypted key file exists at the specified path
- Check file permissions (should be readable by current user)
- Verify the path is correct (use `-ef` option to specify custom path)

### "Decryption failed"

**Password provider:**
- Verify you're using the correct passphrase
- Try clearing cache: `vhsm clear-cache`
- Re-encrypt if needed: `vhsm encrypt`

**FIDO2 provider:**
- Ensure you're using the SAME authenticator that was used for encryption
- For Windows Hello: Must be same Windows account
- For security keys: Must be same physical key
- For mobile: Must be same device/account
- Try a different browser (Chrome/Edge recommended)

### FIDO2: Browser doesn't open automatically

- Manually navigate to `http://localhost:8765`
- Check that your browser supports WebAuthn
- Ensure no firewall is blocking localhost connections

### FIDO2: "No authenticator found"

- **For security keys**: Check device is plugged in firmly, try different USB port
- **For Windows Hello**: Ensure it's set up in Windows Settings → Accounts → Sign-in options
- **For mobile**: Ensure your phone has biometric authentication enabled
- Close other apps using the authenticator
- Try different browser (Chrome/Edge recommended)
- Restart browser

### FIDO2: "SecurityError" in browser

- Ensure you're accessing `localhost`, not `127.0.0.1`
- Some browsers require HTTPS, but localhost is exempt
- Try a different browser

### Cache not working

- Check that caching is enabled: `vhsm run --cache-timeout 3600000 -- npm start`
- Verify the key ID hasn't changed (different encrypted keys = different cache entries)
- Clear cache and retry: `vhsm clear-cache`

---

## Security Notes

### Password Provider

- ✅ Keys are encrypted with AES-256-GCM
- ✅ Decrypted keys only exist in memory
- ✅ Session cache expires after 1 hour
- ✅ Never commit `.env.keys.encrypted` to version control
- ⚠️ If someone has your passphrase and encrypted file, they can decrypt

### FIDO2 Provider

- ✅ Keys are encrypted with AES-256-GCM
- ✅ Decryption requires physical authentication (touch, PIN, biometric)
- ✅ Encryption key is derived from FIDO2 credential
- ✅ Session cache is memory-only and expires
- ⚠️ If someone has your authenticator, they can decrypt (requires physical access)

---

## Next Steps

- See [README.md](./README.md) for advanced configuration and all available providers
- Check [EXAMPLE.md](./EXAMPLE.md) for more usage examples
- Read [FIDO2-GUIDE.md](./FIDO2-GUIDE.md) for detailed FIDO2 documentation
- Explore [EXEC-FEATURE.md](./EXEC-FEATURE.md) for programmatic function execution
- Try other providers: `vhsm encrypt -p dpapi` (Windows) or `vhsm encrypt -p tpm2` (Linux/macOS)

