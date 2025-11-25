# TPM2 Provider Setup Guide

The TPM2 provider uses your computer's Trusted Platform Module (TPM) chip for hardware-backed encryption. This provides significantly stronger security than software-only encryption.

## Security Benefits

### Why TPM2?

| Feature | Password Only | DPAPI | **TPM2** |
|---------|--------------|--------|----------|
| Hardware-backed | ❌ | ❌ | ✅ |
| User authentication | ✅ | ✅ | ✅ (optional) |
| Machine-bound | ❌ | ✅ | ✅ |
| Survives OS compromise | ❌ | ❌ | ✅ |
| Requires physical access | ❌ | ❌ | ✅ |

**Key Security Features:**
- 🔐 Keys sealed in hardware - cannot be extracted even with admin access
- 🔒 Survives memory dumps and OS-level attacks
- 🛡️ Optional PIN/password adds second factor
- 🏢 Meets enterprise security compliance requirements

## Prerequisites

### 1. Check for TPM2 Hardware

**Windows:**
```powershell
tpm.msc
# Opens TPM Management Console
# Look for "TPM Manufacturer Information"
```

Or use PowerShell:
```powershell
Get-Tpm
# Should show TpmPresent: True
```

**Linux:**
```bash
# Check if TPM device exists
ls /dev/tpm*

# Get TPM info
sudo dmesg | grep -i tpm
```

Most computers manufactured after 2016 have TPM 2.0. If you don't have one, you can use software TPM simulators for testing.

### 2. Install tpm2-tools

**Windows:**
```powershell
# Using Chocolatey
choco install tpm2-tools

# Or download from: https://github.com/tpm2-software/tpm2-tools/releases
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install tpm2-tools
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install tpm2-tools
```

**macOS:**
```bash
# Note: macOS doesn't have TPM hardware
# You can install tools but will need a software simulator
brew install tpm2-tools
```

### 3. Verify Installation

```bash
tpm2_getrandom --help
# Should display help text without errors
```

## Usage

### Encrypt with TPM2

```bash
# Interactive (prompts for optional auth password)
vhsm encrypt -p tpm2

# With auth password (for extra security)
vhsm encrypt -p tpm2 -pw "your-auth-password"

# Without auth password (hardware-only protection)
vhsm encrypt -p tpm2 --no-password

# Multiple env files
vhsm encrypt -p tpm2 -f .env.local -f .env.production
```

### Security Modes

**Mode 1: Hardware-only (No auth password)**
```bash
vhsm encrypt -p tpm2
# When prompted: Answer "No" to auth password

# Decryption: Seamless, no password prompt
vhsm run node server.js
```
- ✅ Protected by TPM hardware
- ✅ Cannot be decrypted on different machine
- ❌ No user authentication required

**Mode 2: Hardware + Auth Password (Recommended)**
```bash
vhsm encrypt -p tpm2 -pw "MySecurePassword123"

# Decryption: Requires password
vhsm run -pw "MySecurePassword123" node server.js
```
- ✅ Protected by TPM hardware
- ✅ Cannot be decrypted on different machine
- ✅ Requires password for each use
- 🎯 **Best security**: Combines "something you have" (TPM) with "something you know" (password)

### Run with TPM2-encrypted keys

```bash
# If encrypted without auth
vhsm run node server.js

# If encrypted with auth
vhsm run -pw "your-auth-password" node server.js

# Multiple env files
vhsm run -f .env.local -f .env.production node server.js
```

### Decrypt and Restore

```bash
# Decrypt and restore to .env.keys
vhsm decrypt -p tpm2 --restore

# With auth password
vhsm decrypt -p tpm2 -pw "your-auth-password" --restore
```

## Encrypted File Format

Keys encrypted with TPM2 are stored with the `tpm2:` prefix:

```
#/-----------------!VHSM_PRIVATE_KEYS!------------------/
#/ VHSM encrypted keys. DO NOT commit to source control /
#/------------------------------------------------------/

VHSM_PRIVATE_KEY=tpm2:eyJwdWIiOiJBUUFCQUFzQUJnQUFBQWdBSUFBL...
VHSM_PRIVATE_KEY_LOCAL=tpm2:eyJwdWIiOiJBUUFCQUFzQUJnQUFBQWdBSU...
```

The value is a base64-encoded JSON blob containing:
- TPM public key
- TPM private key (sealed)
- Auth requirement flag

## Security Considerations

### ✅ TPM2 Protects Against:

- **Memory dumps** - Keys sealed in hardware chip
- **Disk forensics** - Only sealed blobs on disk
- **Malware** - Cannot extract keys from TPM
- **Different machine** - TPM-bound, won't decrypt elsewhere
- **Stolen files** - Useless without the specific TPM

### ⚠️ TPM2 Does NOT Protect Against:

- **Physical TPM extraction** (requires specialized hardware, very difficult)
- **Authorized local processes** (if running as your user, can access TPM)
- **TPM reset/clear** (will lose all sealed keys - treat as data loss)

### 🎯 Best Practices:

1. **Use auth passwords** for production environments
2. **Backup sealed keys** (though they only work on that machine)
3. **Document machine identity** (hostname, serial) for disaster recovery
4. **Consider BitLocker/dm-crypt** for additional disk encryption
5. **Rotate keys periodically** following your security policy

## Troubleshooting

### TPM not found
```bash
# Check TPM status
tpm2_getrandom 8 --hex

# Clear TPM ownership (CAUTION: Loses all sealed data)
# Windows: tpm.msc → Clear TPM
# Linux: sudo tpm2_clear
```

### Authorization failures
```bash
# Ensure you're using the same auth password as encryption
vhsm decrypt -pw "correct-password" --restore

# If you forgot the password, you'll need to re-encrypt with dotenvx
```

### Permission denied
```bash
# Linux: Add user to tss group
sudo usermod -a -G tss $USER
# Log out and back in

# Or run with sudo (not recommended for daily use)
sudo vhsm encrypt -p tpm2
```

## Performance

TPM operations are slower than software encryption:

| Operation | Password | DPAPI | TPM2 |
|-----------|----------|-------|------|
| Encrypt | ~10ms | ~50ms | ~500ms |
| Decrypt | ~5ms | ~30ms | ~300ms |

The performance trade-off is worth it for the security benefits in production environments.

## Advanced: Mixed Providers

You can use different providers for different environments:

```bash
# Development: Quick DPAPI (Windows)
vhsm encrypt -p dpapi -f .env.local

# Production: Secure TPM2 with auth
vhsm encrypt -p tpm2 -pw "prod-password" -f .env.production

# Result: Mixed .env.keys.encrypted
VHSM_PRIVATE_KEY_LOCAL=dpapi:AQAAANCMnd8BFdERjHoAwE...
VHSM_PRIVATE_KEY_PRODUCTION=tpm2:eyJwdWIiOiJBUUFCQUFz...
```

Each key remembers its provider and uses the correct decryption method automatically!

## Migration from Other Providers

### From Password to TPM2:
```bash
# 1. Decrypt existing keys
vhsm decrypt --restore

# 2. Re-encrypt with TPM2
vhsm encrypt -p tpm2

# 3. Verify
vhsm run node server.js
```

### From DPAPI to TPM2:
```bash
# Same process
vhsm decrypt --restore
vhsm encrypt -p tpm2 -pw "add-auth-password"
```

## Further Reading

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [tpm2-tools Documentation](https://tpm2-tools.readthedocs.io/)
- [TPM Security Best Practices](https://trustedcomputinggroup.org/resource/tpm-best-practices/)

