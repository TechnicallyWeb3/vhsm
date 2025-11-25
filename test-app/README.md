# vhsm Test Application

This is a test application that demonstrates the complete vhsm workflow with dotenvx.

## Setup

### 1. Install Dependencies

```bash
cd test-app
npm install
```

### 2. Install dotenvx (if not already installed)

```bash
npm install -g @dotenvx/dotenvx
# or
npm install --save-dev @dotenvx/dotenvx
```

### 3. Generate dotenvx Key

First, generate a dotenvx private key:

```bash
vhsm encrypt
```

This creates `.env.keys` in the test-app directory.

### 4. Encrypt the Key with vhsm

From the project root (not test-app), encrypt the key:

```bash
# From project root
vhsm encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
```

You'll be prompted for a passphrase. Remember this passphrase!

### 5. Secure the Files

```bash
cd test-app
chmod 600 .env.keys.encrypted
chmod 600 .env.keys  # If you keep it (not recommended)
```

Add to `.gitignore`:
```
.env
.env.keys
.env.keys.encrypted
```

## Usage

### Run with vhsm

From the project root:

```bash
# Run the server
vhsm run -ef test-app/.env.keys.encrypted -- node test-app/server.js

# Or use npm script (if configured)
cd test-app
vhsm run -k .env.keys.encrypted -- npm start
```

### Test Environment Variables

```bash
vhsm run -k test-app/.env.keys.encrypted -- node test-app/test-env.js
```

### Run Demo

```bash
vhsm run -k test-app/.env.keys.encrypted -- node test-app/demo.js
```

## Workflow Demonstration

### Complete Flow

1. **Encrypt the key**:
   ```bash
   vhsm encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
   ```

2. **Run with vhsm** (first time - will prompt for passphrase):
   ```bash
   vhsm run -ef test-app/.env.keys.encrypted -- node test-app/server.js
   ```

3. **Run again** (cached - no prompt):
   ```bash
   vhsm run -ef test-app/.env.keys.encrypted -- node test-app/server.js
   ```

4. **Clear cache** (next run will prompt again):
   ```bash
   vhsm clear-cache
   ```

## What This Demonstrates

- ✅ Encrypted key storage (`.env.keys.encrypted`)
- ✅ Runtime decryption with passphrase prompt
- ✅ Secure injection of `DOTENV_PRIVATE_KEY` to dotenvx
- ✅ Environment variables loaded securely
- ✅ Session caching (no repeated prompts)
- ✅ In-memory only key handling

## Troubleshooting

### "dotenvx: command not found"

Install dotenvx:
```bash
npm install -g @dotenvx/dotenvx
```

### "Failed to read encrypted key file"

- Check the path: `-k test-app/.env.keys.encrypted`
- Ensure the file exists
- Check file permissions

### "Decryption failed"

- Verify you're using the correct passphrase
- Try clearing cache: `vhsm clear-cache`
- Re-encrypt if needed: `vhsm encrypt test-app/.env.keys -o test-app/.env.keys.encrypted`

### Environment variables not loading

- Ensure `.env` file exists in `test-app/`
- Verify dotenvx is working: `dotenvx run -- node test-app/test-env.js`
- Check that the encrypted key is correct

