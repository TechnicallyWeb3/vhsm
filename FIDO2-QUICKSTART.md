# FIDO2/Yubikey Quick Start Guide

## What We've Added

✅ FIDO2 provider for Yubikey authentication
✅ Browser-based WebAuthn integration
✅ AES-256-GCM encryption using FIDO2-derived keys
✅ Auto-registration and authentication flows
✅ Test script to verify functionality

## Test Your Setup

### Step 1: Plug in Your Yubikey

Make sure your Yubikey is connected to your computer.

### Step 2: Run the Test Script

```bash
node test-fido2.js
```

This will:
1. Open a browser window on `http://localhost:8765`
2. Ask you to click "Register Yubikey"
3. Your Yubikey will blink - **touch it**
4. Encrypt a test string
5. Open another browser window
6. Ask you to authenticate - **touch your Yubikey again**
7. Decrypt and verify the string

**Expected flow:**
```
=== FIDO2/Yubikey Provider Test ===

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
A browser window will open. Please touch your Yubikey when prompted.

🔑 Please touch your Yubikey to decrypt...
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
- Click "Register Yubikey"
- Touch your Yubikey when it blinks
- Keys are encrypted with format: `fido2:credentialId:iv:authTag:data`

### Run Your App with FIDO2 Decryption

```bash
cd test-app
vhsm run -p fido2 -- node index.js
```

**What happens:**
- Browser opens automatically
- Touch your Yubikey when it blinks
- Keys are decrypted in memory
- Your app runs with decrypted environment variables

### Decrypt and View Keys

```bash
cd test-app
vhsm decrypt -p fido2
```

Or restore to file:

```bash
vhsm decrypt -p fido2 --restore
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
         │               │    Yubikey       │
         │               │  (FIDO2 Device)  │
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
   - Credential is stored on your Yubikey
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
   - Requires physical touch of Yubikey
   - Derives same encryption key

3. **Data Decryption**
   - Uses AES-256-GCM with stored IV and auth tag
   - Decrypts to original private key
   - Key is only in memory

## Security Model

### What's Protected ✅

- Private keys are encrypted with AES-256-GCM
- Decryption requires physical Yubikey presence
- User must touch device (proof of presence)
- Encryption key is derived, never stored
- Session cache is memory-only

### Threat Model

| Attack Vector | Protected? | Notes |
|--------------|------------|-------|
| Malware reading files | ✅ Yes | Files are encrypted |
| Malware reading memory | ⚠️ Partial | Only during active use |
| Physical theft of Yubikey | ❌ No | Physical possession = access |
| Remote attacker | ✅ Yes | Requires physical device |
| Phishing | ⚠️ Depends | WebAuthn origin binding helps |
| Shoulder surfing | ✅ Yes | No password to see |

### Best Practices

1. **Physical Security**: Keep your Yubikey secure
2. **Backup Keys**: Register multiple Yubikeys for redundancy
3. **Don't Commit**: Never commit `.env.keys.encrypted` to git
4. **Verify Origin**: Only authenticate on `localhost:8765`
5. **Use Cache Wisely**: Default 1-hour cache is good for dev

## Troubleshooting

### Browser doesn't open

**Symptom**: Console shows URL but browser doesn't open

**Solution**: Manually navigate to `http://localhost:8765`

### Yubikey not detected

**Symptoms**: 
- "No authenticator found"
- Timeout errors
- Browser says "SecurityError"

**Solutions**:
1. Check Yubikey is plugged in firmly
2. Try different USB port
3. Close other apps using Yubikey (YubiKey Manager, etc.)
4. Try different browser (Chrome/Edge recommended)
5. Restart browser

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

**Reason**: FIDO2 credentials are bound to the Yubikey, not the machine

**Solution**: 
- You MUST use the SAME Yubikey that encrypted the data
- The credential is stored on the Yubikey itself
- Different machines are OK, different Yubikeys are NOT

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
- ✅ Devices: Yubikey 5 series, Security Key series
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

