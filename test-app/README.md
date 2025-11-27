# vhsm Test Application

This is a test application that demonstrates the complete vhsm workflow with dotenvx.

## Setup

### 1. Install Dependencies

```bash
cd test-app
npm install
```

### 2. Install vhsm (includes dotenvx)

```bash
npm install -g vhsm
```

No need to install dotenvx separately - vhsm includes it as a dependency.

### 3. Generate dotenvx Key

First, generate a dotenvx private key:

```bash
vhsm encrypt
```

This creates `.env.keys` in the test-app directory.

### 4. Encrypt the Key with vhsm

From the project root (not test-app), encrypt the key with your preferred provider:

```bash
# Password (default)
vhsm encrypt

# Windows DPAPI (no passphrase prompts)
vhsm encrypt -p dpapi

# FIDO2 (Windows Hello, security keys, mobile - browser flow)
vhsm encrypt -p fido2
```

For password provider, you'll be prompted for a passphrase. DPAPI and FIDO2 flows take care of the protection automatically.

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
# Run the server (auto-detects provider from encrypted file)
vhsm run -- node test-app/server.js

# Or use npm script (if configured)
cd test-app
vhsm run -- npm start
```

Or add it to your npm scripts in package.json:

```json
// package.json scripts example:
// In your app's package.json, add scripts like:
{
  "scripts": {
    "start": "node server.js",
    "demo": "node demo.js",
    "test-env": "node test-env.js",
    "secure": "vhsm run -- node server.js"
  }
}
```

You can then run your app securely using npm scripts like these:

```bash
# This will run server.js with secure key decryption via vhsm:
npm run secure

# Or you can use vhsm run to wrap any script:
vhsm run -- npm run start
vhsm run -- npm run demo
vhsm run -- npm run test-env
```

> **Tip:** If you want all developers to run securely by default, just replace the `start` script in `package.json` with the `vhsm run -- node server.js` command.

```


### Test Environment Variables

```bash
vhsm run -ef test-app/.env.keys.encrypted -- node test-app/test-env.js
```

### Run Demo

```bash
vhsm run -ef test-app/.env.keys.encrypted -- node test-app/demo.js
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

3. **Run again** (cached - may still need authentication depending on provider):
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

This shouldn't happen as vhsm includes dotenvx. If you see this:
```bash
npm install -g vhsm
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

