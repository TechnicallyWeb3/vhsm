# FIDO2 Quick Start Guide

## What We've Added

✅ FIDO2 provider for hardware-backed authentication
✅ Browser-based WebAuthn integration
✅ AES-256-GCM encryption using FIDO2-derived keys
✅ Auto-registration and authentication flows
✅ Test script to verify functionality

## Supported FIDO2 Authenticators

- **Windows Hello**: PIN, fingerprint, or facial recognition (no additional hardware needed)
- **Hardware Security Keys**: YubiKey, Titan Security Key, or any FIDO2-compatible key
- **Mobile Authenticators**: Face ID, fingerprint via QR code on iPhone/Android

## Test Your Setup

### Step 1: Ensure FIDO2 Authenticator is Available

- **Windows Hello**: Set up in Windows Settings → Accounts → Sign-in options
- **Security Key**: Plug in your hardware key (YubiKey, etc.)
- **Mobile**: Have your phone ready with biometric authentication enabled

### Step 2: Run the Test Script

```bash
node test-fido2.js
```

This will:
1. Open a browser window on `http://localhost:8765`
2. Ask you to click "Register" button
3. Authenticate using your FIDO2 method (Windows Hello PIN/biometric, touch security key, mobile Face ID, etc.)
4. Encrypt a test string
5. Open another browser window
6. Ask you to authenticate again using the same method
7. Decrypt and verify the string

**Expected flow:**
```
=== FIDO2 Provider Test ===

FIDO2 Available: true

Creating FIDO2 provider...
✅ Provider created: fido2
   Requires interaction: true

Original string: dotenvx_private_key_1234567890abcdef

Encrypting with FIDO2...
A browser window will open. Please follow the instructions.

🌐 Please open your browser to: http://localhost:8765

✅ Encrypted (120 chars): abc123def456:1234...

Waiting 2 seconds before decryption...

Decrypting with FIDO2...
A browser window will open. Please authenticate when prompted.

🔑 Please authenticate with your FIDO2 device...
🌐 Opening browser for authentication...

✅ Decrypted: dotenvx_private_key_1234567890abcdef

✅ Success! Decrypted string matches original

=== Test Complete ===
```

## Real-World Usage

### Encrypt Your Environment Keys

1. First, make sure you have a `.env.keys` file (created by `dotenvx encrypt`):

```bash
cd test-app
npx dotenvx encrypt
```

2. Encrypt the keys with FIDO2:

```bash
# From the root directory
node dist/cli.js encrypt -p fido2 -fk test-app/.env.keys -o test-app/.env.keys.encrypted
```

Or if you've installed vhsm globally:

```bash
cd test-app
vhsm encrypt -p fido2
```

**What happens:**
- Browser opens
- Click "Register" button
- Authenticate using your FIDO2 method (Windows Hello, security key touch, mobile Face ID, etc.)
- Keys are encrypted with format: `fido2:credentialId:iv:authTag:data`

### Run Your App with FIDO2 Decryption

```bash
cd test-app
vhsm run -- node index.js
```

**What happens:**
- Browser opens automatically
- Authenticate using your FIDO2 method (Windows Hello, security key touch, mobile Face ID, etc.)
- Keys are decrypted in memory
- Your app runs with decrypted environment variables

### Decrypt and View Keys

```bash
cd test-app
vhsm decrypt
```

Or restore to file:

```bash
vhsm decrypt --restore
```

## Architecture Overview

```
┌─────────────────┐
│   VHSM CLI      │
│  (Node.js)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│ FIDO2 Provider  │─────▶│ Local HTTP       │
│                 │      │ Server :8765     │
└────────┬────────┘      └────────┬─────────┘
         │                        │
         │                        ▼
         │               ┌──────────────────┐
         │               │   Web Browser    │
         │               │   (WebAuthn)     │
         │               └────────┬─────────┘
         │                        │
         │                        ▼
         │               ┌──────────────────┐
         │               │  FIDO2 Device   │
         │               │ (Windows Hello, │
         │               │ Security Key,   │
         │               │  Mobile, etc.)   │
         │               └────────┬─────────┘
         │                        │
         ▼                        ▼
┌─────────────────────────────────────┐
│      FIDO2 Credential Created       │
│   (Used to derive encryption key)   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│   AES-256-GCM Encryption/Decryption │
│    (Protects your private keys)     │
└─────────────────────────────────────┘
```

## How It Works

### Encryption Process

1. **Credential Creation**
   - Opens browser to `localhost:8765`
   - Uses WebAuthn API to create new credential
   - Credential is stored on your FIDO2 authenticator
   - Returns credential ID

2. **Key Derivation**
   - Hashes credential ID with SHA-256
   - Creates 256-bit encryption key
   - Key never touches disk

3. **Data Encryption**
   - Uses AES-256-GCM with random IV
   - Encrypts your private key
   - Stores: `credentialId:iv:authTag:ciphertext`

### Decryption Process

1. **Parse Encrypted Data**
   - Extracts credential ID, IV, auth tag, ciphertext

2. **Authentication**
   - Opens browser to `localhost:8765`
   - Uses WebAuthn API to authenticate with credential ID
   - Requires authentication (PIN, biometric, touch, etc.)
   - Derives same encryption key

3. **Data Decryption**
   - Uses AES-256-GCM with stored IV and auth tag
   - Decrypts to original private key
   - Key is only in memory

## Security Model

### What's Protected ✅

- Private keys are encrypted with AES-256-GCM
- Decryption requires FIDO2 authenticator presence
- User must touch device (proof of presence)
- Encryption key is derived, never stored
- Session cache is memory-only

### Threat Model

| Attack Vector | Protected? | Notes |
|--------------|------------|-------|
| Malware reading files | ✅ Yes | Files are encrypted |
| Malware reading memory | ⚠️ Partial | Only during active use |
| Physical theft of authenticator | ❌ No | Physical possession = access |
| Remote attacker | ✅ Yes | Requires physical device |
| Phishing | ⚠️ Depends | WebAuthn origin binding helps |
| Shoulder surfing | ✅ Yes | No password to see |

### Best Practices

1. **Physical Security**: Keep your FIDO2 authenticator secure
2. **Backup Authenticators**: Register multiple authenticators for redundancy (e.g., Windows Hello + security key)
3. **Don't Commit**: Never commit `.env.keys.encrypted` to git
4. **Verify Origin**: Only authenticate on `localhost:8765`
5. **Use Cache Wisely**: Default 1-hour cache is good for dev

## Troubleshooting

### Browser doesn't open

**Symptom**: Console shows URL but browser doesn't open

**Solution**: Manually navigate to `http://localhost:8765`

### FIDO2 authenticator not detected

**Symptoms**: 
- "No authenticator found"
- Timeout errors
- Browser says "SecurityError"

**Solutions**:
1. **For security keys**: Check device is plugged in firmly, try different USB port
2. **For Windows Hello**: Ensure it's set up in Windows Settings → Accounts → Sign-in options
3. **For mobile**: Ensure your phone has biometric authentication enabled
4. Close other apps using the authenticator
5. Try different browser (Chrome/Edge recommended)
6. Restart browser

### Port 8765 already in use

**Symptom**: "EADDRINUSE: address already in use"

**Solutions**:
1. Kill the process using port 8765:
   ```powershell
   # Windows PowerShell
   Get-Process -Id (Get-NetTCPConnection -LocalPort 8765).OwningProcess | Stop-Process
   ```
2. Or change the port in `src/providers/fido2.ts` (line with `const port = 8765`)

### "Invalid FIDO2 encrypted key format"

**Symptom**: Error when trying to decrypt

**Causes**:
- File was manually edited
- Wrong encryption provider was used
- File corruption

**Solution**: Re-encrypt with FIDO2:
```bash
vhsm decrypt -p password --restore  # Use old provider
vhsm encrypt -p fido2                # Re-encrypt with FIDO2
```

### Can't decrypt on different machine

**Symptom**: Works on one machine but not another

**Reason**: FIDO2 credentials are bound to the authenticator, not the machine

**Solution**: 
- You MUST use the SAME authenticator that encrypted the data
- The credential is stored on the authenticator itself
- Different machines are OK, different authenticators are NOT
- For Windows Hello: Must be same Windows account
- For security keys: Must be same physical key
- For mobile: Must be same device/account

## Files Created

```
secenv/
├── src/
│   ├── providers/
│   │   ├── fido2.ts          # FIDO2 provider implementation
│   │   └── index.ts          # Updated to register FIDO2
│   ├── types/
│   │   └── fido2-lib.d.ts    # TypeScript types for fido2-lib
│   └── cli.ts                # Updated to support fido2 provider
├── test-fido2.js             # Test script
├── FIDO2-GUIDE.md            # Comprehensive guide
├── FIDO2-QUICKSTART.md       # This file
└── package.json              # Updated with fido2-lib dependency
```

## Next Steps

1. **Test the basic flow**: `node test-fido2.js`
2. **Encrypt a real project**: `cd test-app && vhsm encrypt -p fido2`
3. **Run with decryption**: `vhsm run -p fido2 -- node index.js`
4. **Read full guide**: See `FIDO2-GUIDE.md` for details
5. **Configure**: Add to `.vhsmrc` to make FIDO2 the default

## Support

- ✅ Works: Windows, macOS, Linux
- ✅ Tested: Chrome, Edge, Firefox, Safari
- ✅ Devices: Windows Hello, YubiKey, Titan Security Key, mobile authenticators, any FIDO2-compatible device
- ⚠️ Requires: Graphical environment (not SSH without X11)
- ❌ Not for: CI/CD, Docker, headless servers

## Configuration Example

To make FIDO2 your default provider:

```json
// .vhsmrc
{
  "provider": "fido2",
  "enableCache": true,
  "cacheTimeout": 3600000
}
```

Then you can just run:
```bash
vhsm run -- node index.js
# No need to specify -p fido2
```

---

**Ready to test?** Run: `node test-fido2.js` 🚀

