# Test Application Summary

This test application demonstrates the complete vhsm workflow with a real Node.js application.

## What It Demonstrates

✅ **Complete Encryption Flow**
- Encrypting dotenvx private keys with passphrase
- Secure storage of encrypted keys

✅ **Runtime Decryption**
- Prompting for passphrase at runtime
- In-memory decryption (never touches disk)

✅ **dotenvx Integration**
- Seamless integration with dotenvx
- Environment variable loading

✅ **Session Caching**
- First run: prompts for passphrase
- Subsequent runs: uses cached key (no prompt)

✅ **Security Best Practices**
- Encrypted keys with secure permissions
- No plaintext keys in process memory
- Sanitized error handling

## Files

### Application Files
- `server.js` - Simple HTTP server that displays environment variables
- `test-env.js` - Script to verify environment variables are loaded
- `demo.js` - Demo script showing vhsm workflow
- `create-env.js` - Helper to create .env file

### Setup Files
- `setup.sh` / `setup.ps1` - Automated setup scripts
- `demo-flow.sh` / `demo-flow.ps1` - Complete workflow demonstration

### Documentation
- `README.md` - Detailed setup and usage instructions
- `QUICKSTART.md` - Quick start guide
- `SUMMARY.md` - This file

## Quick Test

From project root:

```bash
# Windows PowerShell
.\test-app\demo-flow.ps1

# Linux/Mac
bash test-app/demo-flow.sh

# Or manually:
cd test-app
npm install
node create-env.js
dotenvx encrypt
cd ..
node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js
```

## Expected Output

When running the server, you should see:

```
Enter passphrase to decrypt dotenvx private key: ****
🚀 Starting test server...

Environment Variables Loaded:
──────────────────────────────────────────────────
NODE_ENV: development
PORT: 3000
DATABASE_URL: postgresql://localhost:5432/testdb
API_KEY: ***2345
SECRET_TOKEN: ***t-xyz
──────────────────────────────────────────────────

✅ Server would start on port 3000
✅ Environment variables are loaded and secure!
```

## Verification Checklist

- [ ] Encrypted key file exists: `test-app/.env.keys.encrypted`
- [ ] First run prompts for passphrase
- [ ] Environment variables load correctly
- [ ] Second run uses cache (no prompt)
- [ ] No plaintext `.env.keys` needed after encryption
- [ ] Error messages don't leak secrets

## Integration Points

This test app shows how to integrate vhsm into your own projects:

1. **Encrypt your dotenvx key**: `vhsm encrypt .env.keys -o .env.keys.encrypted`
2. **Update your scripts**: Replace `dotenvx run` with `vhsm run`
3. **Secure the files**: Add to `.gitignore`, set permissions
4. **Share securely**: Use password manager or secure channels for passphrase

## Next Steps

- Integrate vhsm into your own project
- Explore custom providers (see `src/providers/README.md`)
- Configure caching for your workflow
- Set up team-wide passphrase management

