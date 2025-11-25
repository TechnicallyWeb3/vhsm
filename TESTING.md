# Testing Guide

This guide covers testing all three providers: Password, DPAPI, and TPM2.

## Prerequisites

### Check Your System

```bash
# Check if TPM2 tools are installed
tpm2_getrandom --help

# If not installed:
# Windows: choco install tpm2-tools
# Linux: sudo apt install tpm2-tools
```

## Quick Test - All Providers

### 1. Automated Provider Tests

```bash
# Build the project
npm run build

# Test TPM2 provider (if available)
node test-tpm2.js
```

Expected output:
```
=== TPM2 Provider Test ===

Platform: win32
TPM2 Tools Available: true

Creating TPM2 provider...
✅ Provider created: tpm2
   Requires interaction: true

--- Test 1: Without Authorization Password ---
✅ Encrypted
✅ Decrypted
✅ Test 1 PASSED

--- Test 2: With Authorization Password ---
✅ Encrypted
✅ Decrypted
✅ Test 2 PASSED

--- Test 3: Wrong Password (Should Fail) ---
✅ Test 3 PASSED: Correctly rejected wrong password

--- Test 4: Missing Required Password (Should Fail) ---
✅ Test 4 PASSED: Correctly required password

✅ All Tests PASSED!
```

### 2. Manual End-to-End Test

**Step 1: Create test environment**
```bash
cd test-app

# Create test .env files if they don't exist
echo "TEST_KEY=test_value" > .env.test
```

**Step 2: Test with Password Provider**
```bash
# Encrypt
node ../dist/cli.js encrypt -f .env.test -pw "TestPassword123"

# Verify file created
cat .env.keys.encrypted
# Should see: VHSM_PRIVATE_KEY_TEST=encrypted:...

# Run (decrypt and execute)
node ../dist/cli.js run -f .env.test -pw "TestPassword123" -- node -e "console.log('Password provider works!')"

# Decrypt and restore
node ../dist/cli.js decrypt -f .env.test -pw "TestPassword123" --restore
cat .env.keys
# Should see: DOTENV_PRIVATE_KEY_TEST=...
```

**Step 3: Test with DPAPI Provider (Windows only)**
```bash
# Clean up previous test
rm .env.keys.encrypted .env.keys

# Encrypt with DPAPI
node ../dist/cli.js encrypt -p dpapi -f .env.test

# Verify
cat .env.keys.encrypted
# Should see: VHSM_PRIVATE_KEY_TEST=dpapi:...

# Run (no password needed!)
node ../dist/cli.js run -f .env.test -- node -e "console.log('DPAPI provider works!')"

# Decrypt and restore
node ../dist/cli.js decrypt -f .env.test --restore
```

**Step 4: Test with TPM2 Provider**
```bash
# Clean up previous test
rm .env.keys.encrypted .env.keys

# Encrypt with TPM2 (with auth)
node ../dist/cli.js encrypt -p tpm2 -f .env.test -pw "SecureTPM123"

# Verify
cat .env.keys.encrypted
# Should see: VHSM_PRIVATE_KEY_TEST=tpm2:...

# Run (requires auth password)
node ../dist/cli.js run -f .env.test -pw "SecureTPM123" -- node -e "console.log('TPM2 provider works!')"

# Decrypt and restore
node ../dist/cli.js decrypt -f .env.test -pw "SecureTPM123" --restore
```

**Step 5: Test Mixed Providers**
```bash
# Create multiple env files
echo "DEV_KEY=dev" > .env.dev
echo "PROD_KEY=prod" > .env.prod

# Encrypt dev with DPAPI (fast, convenient)
node ../dist/cli.js encrypt -p dpapi -f .env.dev

# Encrypt prod with TPM2 (secure, hardware-backed)
node ../dist/cli.js encrypt -p tpm2 -f .env.prod -pw "ProdPassword"

# Verify mixed providers
cat .env.keys.encrypted
# Should see:
# VHSM_PRIVATE_KEY_DEV=dpapi:...
# VHSM_PRIVATE_KEY_PROD=tpm2:...

# Run with dev (no password)
node ../dist/cli.js run -f .env.dev -- node -e "console.log('Dev with DPAPI')"

# Run with prod (requires password)
node ../dist/cli.js run -f .env.prod -pw "ProdPassword" -- node -e "console.log('Prod with TPM2')"

# Run with both!
node ../dist/cli.js run -f .env.dev -f .env.prod -pw "ProdPassword" -- node -e "console.log('Mixed providers work!')"
```

## Integration Test with Real App

**Step 1: Setup test app**
```bash
cd test-app

# Make sure you have a .env file
cat .env
```

**Step 2: Encrypt with your preferred provider**
```bash
# Option A: Password (portable, works everywhere)
vhsm encrypt -pw "MyPassword123"

# Option B: DPAPI (Windows, no password, user-bound)
vhsm encrypt -p dpapi

# Option C: TPM2 (hardware-backed, maximum security)
vhsm encrypt -p tpm2 -pw "SecurePassword"
```

**Step 3: Test the server**
```bash
# Run the test server
vhsm run node server.js

# In another terminal, test it
curl http://localhost:3000
# Should see: {"message":"Hello from vhsm test app!","env":"..."}
```

**Step 4: Test demo flow**
```bash
# Run the automated demo
node demo.js
```

## Testing Security Features

### Test 1: Verify Keys Are Encrypted

```bash
# After encryption, check the encrypted file
cat .env.keys.encrypted

# Should NOT see plaintext keys
# Should see something like:
# VHSM_PRIVATE_KEY=tpm2:eyJwdWIiOiJBUUFCQUFz...
```

### Test 2: Verify Original Keys Are Deleted

```bash
# After encryption with default settings
ls -la .env.keys
# Should get: No such file or directory

# If you used --no-delete flag
ls -la .env.keys
# File should still exist
```

### Test 3: Test Wrong Password Rejection

```bash
# Encrypt with password
vhsm encrypt -pw "CorrectPassword"

# Try to decrypt with wrong password
vhsm run -pw "WrongPassword" -- echo "test"
# Should fail with authentication error
```

### Test 4: Test Machine-Binding (TPM2/DPAPI)

```bash
# Encrypt with TPM2 or DPAPI
vhsm encrypt -p tpm2

# Copy .env.keys.encrypted to another machine
# Try to decrypt on the other machine
# Should fail - keys are bound to the original machine's hardware
```

### Test 5: Test Cache Functionality

```bash
# Run first time (will prompt for password)
time vhsm run -f .env -- echo "First run"

# Run second time immediately (should use cache)
time vhsm run -f .env -- echo "Second run"
# Should be faster, no password prompt

# Clear cache
vhsm clear-cache

# Run again (will prompt for password again)
time vhsm run -f .env -- echo "After cache clear"
```

## Troubleshooting Tests

### TPM2 Tests Fail

**Error: "TPM2 tools not found"**
```bash
# Install tpm2-tools
# Windows:
choco install tpm2-tools

# Linux:
sudo apt install tpm2-tools

# Verify:
tpm2_getrandom 8 --hex
```

**Error: "Failed to create TPM primary key"**
```bash
# Check TPM status
tpm2_getrandom 8 --hex

# Linux: Check permissions
ls -la /dev/tpm*
# Add user to tss group if needed
sudo usermod -a -G tss $USER
# Log out and back in

# Windows: Check TPM is enabled
tpm.msc
```

**Error: "Authorization failed"**
```bash
# Make sure you're using the same password for encrypt and decrypt
# Password is case-sensitive

# If you forgot the password, you'll need to re-encrypt:
# 1. Restore original .env.keys from backup
# 2. Or decrypt with dotenvx and re-encrypt with vhsm
```

### DPAPI Tests Fail (Windows)

**Error: "DPAPI is only available on Windows"**
- DPAPI only works on Windows
- Use password or TPM2 provider on other platforms

**Error: "Key was encrypted by a different user"**
- DPAPI keys are user-specific
- Cannot decrypt keys encrypted by another Windows user
- Re-encrypt with your user account

### Performance Tests

```bash
# Test encryption speed
time vhsm encrypt -p password -pw "test123"
time vhsm encrypt -p dpapi
time vhsm encrypt -p tpm2 -pw "test123"

# Expected results:
# Password: ~10-50ms
# DPAPI: ~50-100ms
# TPM2: ~500-1000ms (hardware operations are slower but more secure)
```

## CI/CD Testing

For automated testing in CI/CD:

```bash
# Use password provider with environment variable
export VHSM_PASSWORD="ci-test-password"
vhsm encrypt -pw "$VHSM_PASSWORD"
vhsm run -pw "$VHSM_PASSWORD" -- npm test

# Or use non-interactive mode
echo "$VHSM_PASSWORD" | vhsm run -- npm test
```

## What to Test

- [ ] Password encryption/decryption works
- [ ] DPAPI encryption/decryption works (Windows)
- [ ] TPM2 encryption/decryption works
- [ ] TPM2 with auth password works
- [ ] Wrong password is rejected
- [ ] Multiple env files work
- [ ] Mixed providers work
- [ ] Cache functionality works
- [ ] Cache clearing works
- [ ] --restore flag creates .env.keys file
- [ ] Original .env.keys is deleted after encryption
- [ ] --no-delete preserves original .env.keys
- [ ] Real application runs correctly
- [ ] Environment variables are properly decrypted

## Success Criteria

✅ All automated tests pass
✅ Manual tests complete without errors  
✅ Real application runs with encrypted keys
✅ Wrong passwords are rejected
✅ Performance is acceptable for your use case
✅ Keys are properly encrypted in .env.keys.encrypted
✅ No plaintext keys visible after encryption

If all tests pass, you're ready to use vhsm in production! 🎉

