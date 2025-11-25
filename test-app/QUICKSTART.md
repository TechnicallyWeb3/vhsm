# Quick Start Guide

This guide will walk you through setting up and running the vhsm test application.

## Prerequisites

- Node.js 18+
- npm
- `@dotenvx/dotenvx` installed globally or locally

## Step-by-Step Setup

### 1. Install Test App Dependencies

```bash
cd test-app
npm install
```

### 2. Install dotenvx (if needed)

```bash
npm install -g @dotenvx/dotenvx
```

### 3. Create .env File

```bash
node create-env.js
```

Or manually create `.env` with:
```
DATABASE_URL=postgresql://localhost:5432/testdb
API_KEY=test-api-key-12345
SECRET_TOKEN=super-secret-token-xyz
NODE_ENV=development
PORT=3000
```

### 4. Generate dotenvx Key

```bash
dotenvx encrypt
```

This creates `.env.keys` in the test-app directory.

### 5. Encrypt the Key with vhsm

From the **project root** (not test-app):

```bash
# Using built vhsm
node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted

# Or if installed globally
vhsm encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
```

You'll be prompted for a passphrase. **Remember this passphrase!**

### 6. Run the Test Application

From the **project root**:

```bash
# Using built vhsm
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js

# Or if installed globally
vhsm run -k test-app/.env.keys.encrypted -- node test-app/server.js
```

**First run**: You'll be prompted for the passphrase.
**Subsequent runs**: Key is cached, no prompt needed.

## Testing Different Commands

### Test Server

```bash
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js
```

### Test Environment Variables

```bash
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/test-env.js
```

### Run Demo

```bash
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/demo.js
```

## What You Should See

### First Run (with prompt)

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

### Second Run (cached, no prompt)

```
🚀 Starting test server...

Environment Variables Loaded:
──────────────────────────────────────────────────
...
```

## Verify It's Working

1. ✅ **Encrypted key exists**: `test-app/.env.keys.encrypted`
2. ✅ **Environment variables load**: Server shows all env vars
3. ✅ **No plaintext key in process**: Only encrypted key on disk
4. ✅ **Caching works**: Second run doesn't prompt

## Troubleshooting

### "dotenvx: command not found"

```bash
npm install -g @dotenvx/dotenvx
```

### "Failed to read encrypted key file"

- Check you're running from project root
- Verify path: `test-app/.env.keys.encrypted`
- Ensure file exists: `ls test-app/.env.keys.encrypted`

### "Decryption failed"

- Verify passphrase is correct
- Clear cache: `node dist/cli.js clear-cache`
- Re-encrypt: `node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted`

### Environment variables not showing

- Ensure `.env` file exists in `test-app/`
- Verify dotenvx works: `dotenvx run -- node test-app/test-env.js`
- Check encrypted key is correct

## Next Steps

- Try different cache timeouts: `--cache-timeout 600000` (10 minutes)
- Disable caching: `--no-cache`
- Integrate into your own project
- Explore provider system for custom backends

