# FIDO2/Yubikey Encryption Provider Guide

This guide walks you through using FIDO2/Yubikey as an encryption provider for VHSM.

## Overview

The FIDO2 provider uses your Yubikey (or other FIDO2-compatible security key) to protect your dotenvx private keys. This provides hardware-backed security with the following benefits:

- **Hardware Security**: Keys are derived from FIDO2 credentials stored on your security key
- **User Presence Required**: Physical touch is required for decryption
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **No Password**: No password to remember or forget

## Requirements

1. **FIDO2-Compatible Device**
   - Yubikey 5 series (recommended)
   - Yubikey Security Key series
   - Any other FIDO2/WebAuthn compatible security key

2. **Web Browser**
   - Chrome, Edge, Firefox, Safari, or any modern browser
   - The provider opens a local web page for authentication

3. **Node.js 18+**
   - Required for the VHSM CLI

## How It Works

1. **Encryption**: When you encrypt your keys, the provider:
   - Opens a browser window
   - Creates a FIDO2 credential on your Yubikey
   - Derives an encryption key from the credential
   - Encrypts your private key with AES-256-GCM
   - Stores the credential ID with the encrypted data

2. **Decryption**: When you decrypt your keys, the provider:
   - Opens a browser window
   - Authenticates with your Yubikey using the credential ID
   - Derives the same encryption key
   - Decrypts your private key

3. **Security**: The encryption key is:
   - Derived from the FIDO2 credential ID
   - Never stored on disk
   - Requires physical device presence
   - Unique per registration

## Quick Start

### 1. Test Your Yubikey

First, make sure your Yubikey is working:

```bash
node test-fido2.js
```

This will:
1. Open a browser window
2. Ask you to register your Yubikey
3. Encrypt a test string
4. Ask you to authenticate
5. Decrypt and verify

**Expected Output:**
```
=== FIDO2/Yubikey Provider Test ===

FIDO2 Available: true

Creating FIDO2 provider...
✅ Provider created: fido2
   Requires interaction: true

Original string: dotenvx_private_key_1234567890abcdef

Encrypting with FIDO2...
A browser window will open. Please follow the instructions.

🌐 Opening browser for authentication...

✅ Encrypted: abc123...

Decrypting with FIDO2...
A browser window will open. Please touch your Yubikey when prompted.

🔑 Please touch your Yubikey to decrypt...
🌐 Opening browser for authentication...

✅ Decrypted: dotenvx_private_key_1234567890abcdef

✅ Success! Decrypted string matches original
```

### 2. Encrypt Your .env File

First, if you haven't already, encrypt your .env file with dotenvx:

```bash
# This creates .env.keys with your private keys
npx dotenvx encrypt
```

Then, encrypt the private keys with FIDO2:

```bash
# Encrypt with FIDO2 provider
vhsm encrypt -p fido2

# Or specify custom paths
vhsm encrypt -p fido2 -o .env.keys.encrypted -fk .env.keys
```

**What happens:**
1. A browser window opens
2. You click "Register Yubikey"
3. Your Yubikey blinks - touch it
4. Your keys are encrypted
5. The encrypted keys are saved to `.env.keys.encrypted`
6. The original `.env.keys` is deleted (unless you use `--no-delete`)

**Example `.env.keys.encrypted`:**
```
#/-----------------!VHSM_PRIVATE_KEYS!------------------/
#/ VHSM encrypted keys. DO NOT commit to source control /
#/------------------------------------------------------/

VHSM_PRIVATE_KEY=fido2:abc123def456:1234567890abcdef:fedcba0987654321:encrypted_data_here
```

Format: `fido2:credentialId:iv:authTag:encryptedData`

### 3. Run Your Application

Now you can run your application with encrypted keys:

```bash
# Run with FIDO2 decryption
vhsm run -p fido2 -- node index.js

# Or with specific env files
vhsm run -p fido2 -f .env.production -- npm start
```

**What happens:**
1. A browser window opens automatically
2. Your Yubikey blinks - touch it
3. Keys are decrypted in memory
4. Your application runs with decrypted environment variables
5. Keys are cleared from memory after execution

### 4. Decrypt to View Keys

If you need to view or restore your keys:

```bash
# Decrypt and display
vhsm decrypt -p fido2

# Restore to .env.keys file
vhsm decrypt -p fido2 --restore
```

## Troubleshooting

### Browser doesn't open automatically

If the browser doesn't open, manually navigate to the URL shown in the console:
```
http://localhost:8765
```

### "Yubikey not found" or timeout errors

1. Make sure your Yubikey is plugged in
2. Try a different USB port
3. Check that your browser supports WebAuthn
4. Close other applications using the Yubikey

### "Invalid FIDO2 encrypted key format"

Your encrypted key may be corrupted or from a different provider. Check:
- The key starts with `fido2:` prefix
- The file hasn't been manually edited
- You're using the correct `.env.keys.encrypted` file

### Browser shows "SecurityError"

1. Make sure you're accessing `localhost`, not `127.0.0.1`
2. Some browsers require HTTPS, but localhost is exempt
3. Try a different browser (Chrome/Edge recommended)

### Can't decrypt on a different machine

FIDO2 credentials are tied to the specific Yubikey that created them. To use on a different machine:
1. You need the SAME physical Yubikey
2. The credential must still be stored on that Yubikey
3. Consider using multiple keys for different machines

## Advanced Usage

### Using Multiple Yubikeys

Register a backup Yubikey by re-encrypting:

```bash
# Decrypt with first Yubikey
vhsm decrypt -p fido2 --restore

# Re-encrypt with second Yubikey
vhsm encrypt -p fido2 -fk .env.keys
```

### Custom Configuration

You can configure FIDO2 behavior in `.vhsmrc`:

```json
{
  "provider": "fido2",
  "enableCache": true,
  "cacheTimeout": 3600000
}
```

### Scripting/CI/CD

FIDO2 requires user interaction, so it's not suitable for:
- Automated CI/CD pipelines
- Unattended scripts
- Docker containers

For these scenarios, use `password` or `dpapi` providers instead.

### Headless/SSH Sessions

FIDO2 requires a graphical browser, so it won't work over SSH without X11 forwarding. Options:

1. **Use SSH with X11 forwarding:**
   ```bash
   ssh -X user@host
   ```

2. **Use port forwarding:**
   ```bash
   # On remote machine
   vhsm run -p fido2 -- node app.js
   
   # Forward port 8765 from your local machine
   ssh -L 8765:localhost:8765 user@host
   
   # Open http://localhost:8765 in your local browser
   ```

3. **Use a different provider for remote machines**

## Security Considerations

### What's Protected

✅ Your dotenvx private keys are encrypted with AES-256-GCM
✅ Decryption requires physical device presence
✅ Keys are never stored in plaintext on disk (after encryption)
✅ Session cache is memory-only and time-limited

### What's NOT Protected

⚠️ The encrypted key format includes the credential ID
⚠️ If someone has your Yubikey, they can decrypt (requires physical theft)
⚠️ Browser-based authentication could be phished (use localhost only)
⚠️ Your `.env` files remain encrypted with dotenvx

### Best Practices

1. **Keep your Yubikey secure** - Physical possession = decryption capability
2. **Use backup keys** - Register multiple Yubikeys
3. **Don't commit** `.env.keys.encrypted` to version control
4. **Use cache wisely** - Default 1 hour is good for development
5. **Verify localhost** - Only authenticate on `localhost:8765`

## Comparison with Other Providers

| Feature | FIDO2 | DPAPI | Password |
|---------|-------|-------|----------|
| Hardware-backed | ✅ Yes | ✅ Yes | ❌ No |
| User interaction | ✅ Required | ❌ Not needed | ⚠️ Once per session |
| Cross-platform | ✅ Yes | ❌ Windows only | ✅ Yes |
| Machine-bound | ❌ No* | ✅ Yes | ❌ No |
| CI/CD friendly | ❌ No | ⚠️ Windows only | ✅ Yes |
| Browser required | ✅ Yes | ❌ No | ❌ No |

*FIDO2 is key-bound, not machine-bound - same Yubikey works on any machine

## FAQ

**Q: Can I use multiple Yubikeys?**
A: Each encryption creates a new credential. For multiple keys, decrypt and re-encrypt with each Yubikey.

**Q: What if I lose my Yubikey?**
A: You'll need to restore from backup or decrypt with a backup Yubikey. Keep backups!

**Q: Does this work offline?**
A: Yes! The local web server runs entirely on your machine. No internet required.

**Q: Can I use this in Docker?**
A: Not easily. Docker containers can't access USB devices or display browsers without special configuration.

**Q: Is this secure?**
A: Yes, when used properly. The FIDO2 protocol is designed for security, but physical device access = decryption.

**Q: How is this different from Yubikey OTP?**
A: FIDO2 uses public-key cryptography and is more modern. It's specifically designed for authentication.

**Q: Can I use this with GitHub Codespaces / VS Code Remote?**
A: Port forwarding can work, but local providers (DPAPI, password) are more practical for remote development.

## Next Steps

- Learn about [session caching](./README.md#session-caching)
- Explore [other providers](./README.md#providers)
- Read about [configuration options](./README.md#configuration)
- Check out [CI/CD integration](./README.md#cicd)

## Support

If you encounter issues:

1. Run `node test-fido2.js` to verify basic functionality
2. Check the [Troubleshooting](#troubleshooting) section
3. Verify your Yubikey works with other FIDO2 apps
4. Open an issue with detailed error messages

---

**Note**: This provider is experimental. Test thoroughly before using in production!

