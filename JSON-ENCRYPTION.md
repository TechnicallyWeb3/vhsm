# JSON File Encryption with vHSM

## Overview

vHSM now supports encrypting and decrypting JSON files using the same secure key management system as environment variables. This feature allows you to:

- Encrypt entire JSON configuration files
- Decrypt JSON files on-the-fly in your applications
- Access individual JSON values using dot notation
- Use encrypted JSON values in `vhsm.exec()` alongside environment variables

## How It Works

When you encrypt a JSON file:

1. **Creates a reference file**: `.env.[filename].json` containing a reference to the encrypted file
2. **Encrypts the JSON content**: Using dotenvx encryption format (`encrypted:...`)
3. **Stores the encrypted file**: As `[filename].encrypted.json` with metadata
4. **Saves the encryption key**: Encrypted with vHSM provider in `.env.keys.encrypted`

The encrypted JSON file structure:
```json
{
  "encryptedBy": "vhsm",
  "version": "0.1.13",
  "encryptedValue": "encrypted:..."
}
```

## CLI Usage

### Encrypting JSON Files

```bash
# Encrypt a JSON file (default: password provider)
vhsm encrypt config.json

# Encrypt with specific provider
vhsm encrypt config.json -p fido2

# Encrypt multiple files
vhsm encrypt config.json secrets.json data.json

# Keep original file after encryption
vhsm encrypt config.json --no-delete

# Encrypt with password (for testing)
vhsm encrypt config.json -pw mypassword
```

**Output:**
- `config.encrypted.json` - Encrypted JSON file
- `.env.config.json` - Reference file (can be encrypted with dotenvx)
- `.env.keys.encrypted` - Updated with encryption key

### Decrypting JSON Files

```bash
# Decrypt a JSON file
vhsm decrypt config.encrypted.json

# Decrypt to specific output path
vhsm decrypt config.encrypted.json -o output.json

# Decrypt multiple files
vhsm decrypt config.encrypted.json secrets.encrypted.json

# Decrypt with specific provider
vhsm decrypt config.encrypted.json -p fido2
```

## Programmatic Usage

### Encrypting JSON Files

```typescript
import { encryptJsonFile } from 'vhsm';

await encryptJsonFile('./config.json', {
  provider: 'password',
  password: 'my-secure-password',
  deleteOriginal: false, // Keep original file
  encryptedKeysFile: '.env.keys.encrypted',
});
```

### Loading Entire JSON Files

```typescript
import { loadFile } from 'vhsm';

// Load entire encrypted JSON file
const config = await loadFile('./config.encrypted.json', {
  password: 'my-secure-password',
  enableCache: true, // Cache for 1 hour by default
});

console.log(config);
// { user: { name: 'John' }, apiKey: 'sk_live_...' }
```

### Getting Specific Values with Dot Notation

```typescript
import { getJsonValue } from 'vhsm';

// Get nested value using dot notation
const userName = await getJsonValue(
  './config.encrypted.json',
  'user.name',
  { password: 'my-secure-password' }
);

console.log(userName); // 'John'

// Deep nested access
const dbPassword = await getJsonValue(
  './config.encrypted.json',
  'database.credentials.password',
  { password: 'my-secure-password' }
);
```

## Using JSON Files in exec()

The `vhsm.exec()` function now supports loading encrypted JSON files using the `@vhsm` syntax:

### Load Entire JSON File

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ config }) => {
    // config contains the entire decrypted JSON object
    console.log(config.user.name);
    return config;
  },
  {
    config: '@vhsm config.encrypted.json'
  },
  {
    password: 'my-secure-password',
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

### Access Specific JSON Values

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ userName, apiKey, dbHost }) => {
    // Individual values extracted using dot notation
    console.log(`User: ${userName}`);
    console.log(`API Key: ${apiKey}`);
    console.log(`DB Host: ${dbHost}`);
    
    // Use the values in your logic
    return await connectToDatabase(dbHost, apiKey);
  },
  {
    userName: '@vhsm config.encrypted.json user.name',
    apiKey: '@vhsm config.encrypted.json apiKeys.primary',
    dbHost: '@vhsm config.encrypted.json database.host',
  },
  {
    password: 'my-secure-password',
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

### Mix JSON and Environment Variables

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ userName, apiKey, envVar }) => {
    // Mix JSON values and .env variables
    console.log(`User from JSON: ${userName}`);
    console.log(`API Key from JSON: ${apiKey}`);
    console.log(`Env var from .env: ${envVar}`);
    
    return { userName, apiKey, envVar };
  },
  {
    // From encrypted JSON file
    userName: '@vhsm config.encrypted.json user.name',
    apiKey: '@vhsm config.encrypted.json apiKeys.primary',
    // From encrypted .env file
    envVar: '@vhsm MY_ENV_VARIABLE',
  },
  {
    password: 'my-secure-password',
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

## Example JSON File

Here's an example JSON file that you might want to encrypt:

```json
{
  "user": {
    "name": "John Doe",
    "age": 42,
    "email": "john@example.com"
  },
  "message": "Hello World",
  "apiKeys": {
    "primary": "sk_live_abc123",
    "secondary": "sk_live_xyz789"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "credentials": {
      "username": "admin",
      "password": "super_secret_password"
    }
  }
}
```

After encryption, you can access values like:
- `user.name` → `"John Doe"`
- `user.age` → `42`
- `apiKeys.primary` → `"sk_live_abc123"`
- `database.credentials.password` → `"super_secret_password"`

## Security Features

### Automatic Memory Cleanup

All decrypted JSON values are automatically cleared from memory after use, just like environment variables in `exec()`.

### Session Caching

Decrypted JSON files are cached in memory for improved performance (default: 1 hour). You can disable or configure caching:

```typescript
const config = await loadFile('./config.encrypted.json', {
  enableCache: false, // Disable caching
  // OR
  cacheTimeout: 1800000, // 30 minutes
});
```

### Provider Support

JSON files can be encrypted with any vHSM provider:
- **password** - Password-based encryption
- **dpapi** - Windows Data Protection API (Windows only)
- **fido2** - FIDO2/WebAuthn hardware keys (YubiKey, etc.)
- **tpm2** - TPM 2.0 hardware security module

## API Reference

### `encryptJsonFile(jsonFilePath, options?)`

Encrypts a JSON file using vHSM.

**Parameters:**
- `jsonFilePath` (string) - Path to the JSON file to encrypt
- `options` (EncryptJsonOptions) - Optional encryption options

**Options:**
```typescript
interface EncryptJsonOptions {
  provider?: string;           // Default: 'password' or from config
  password?: string;           // Password for encryption
  deleteOriginal?: boolean;    // Default: true
  outputPath?: string;         // Default: '[filename].encrypted.json'
  encryptedKeysFile?: string;  // Default: '.env.keys.encrypted'
}
```

### `loadFile<T>(jsonFilePath, options?)`

Loads and decrypts a JSON file.

**Parameters:**
- `jsonFilePath` (string) - Path to the encrypted JSON file
- `options` (LoadFileOptions) - Optional decryption options

**Returns:** `Promise<T>` - The decrypted JSON object

**Options:**
```typescript
interface LoadFileOptions {
  encryptedKeysFile?: string;  // Default: '.env.keys.encrypted'
  provider?: string;           // Provider to use
  password?: string;           // Password for decryption
  enableCache?: boolean;       // Default: true
  cacheTimeout?: number;       // Default: 3600000 (1 hour)
}
```

### `getJsonValue<T>(jsonFilePath, path, options?)`

Gets a specific value from a JSON file using dot notation.

**Parameters:**
- `jsonFilePath` (string) - Path to the encrypted JSON file
- `path` (string) - Dot notation path (e.g., 'user.name')
- `options` (LoadFileOptions) - Optional decryption options

**Returns:** `Promise<T>` - The value at the specified path

## File Structure

After encrypting `config.json`, you'll have:

```
project/
├── config.json                    # Original (deleted by default)
├── config.encrypted.json          # Encrypted JSON file
├── .env.config.json              # Reference file
└── .env.keys.encrypted           # Encryption keys (vHSM encrypted)
```

## Best Practices

1. **Add to .gitignore**: Make sure to add encrypted files to `.gitignore` if they contain sensitive data:
   ```
   *.encrypted.json
   .env.*.json
   .env.keys.encrypted
   ```

2. **Use hardware providers in production**: For production environments, use hardware-backed providers like FIDO2 or TPM2 instead of password-based encryption.

3. **Enable caching**: Keep caching enabled in production for better performance.

4. **Use dot notation**: Access only the values you need instead of loading entire JSON files.

5. **Combine with .env files**: Use JSON files for structured configuration and .env files for simple key-value pairs.

## Example: Complete Workflow

```bash
# 1. Create your JSON config file
cat > config.json << EOF
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "credentials": {
      "username": "admin",
      "password": "secret123"
    }
  }
}
EOF

# 2. Encrypt it with vHSM
vhsm encrypt config.json -p fido2

# 3. Use it in your application
```

```typescript
import { exec } from 'vhsm';

// Access specific values in your code
const result = await exec(
  async ({ dbHost, dbPort, dbUser, dbPass }) => {
    const connection = await connectToDatabase({
      host: dbHost,
      port: dbPort,
      user: dbUser,
      password: dbPass,
    });
    return connection;
  },
  {
    dbHost: '@vhsm config.encrypted.json database.host',
    dbPort: '@vhsm config.encrypted.json database.port',
    dbUser: '@vhsm config.encrypted.json database.credentials.username',
    dbPass: '@vhsm config.encrypted.json database.credentials.password',
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

## Debug Mode

To see detailed logging during encryption/decryption, set the `VHSM_DEBUG` environment variable:

```bash
export VHSM_DEBUG=true
vhsm encrypt config.json
```

This will show:
- File paths and key names
- Encryption steps
- File operations
- Any warnings or status messages

Without debug mode, operations are silent (only errors are shown).

## Troubleshooting

### "No encrypted key found for [file]"

Make sure the encryption key is in `.env.keys.encrypted`. The key name should follow the pattern `[FILENAME]_JSON_KEY`.

### "File is not a vHSM encrypted JSON file"

The file format is invalid. Make sure you're loading a file that was encrypted with `vhsm encrypt`.

### "Path not found in JSON file"

Check that the dot notation path is correct and matches the structure of your JSON file.

### "Failed to decrypt JSON content"

Verify that:
1. You're using the correct password/provider
2. The `.env.keys.encrypted` file contains the correct key
3. The encrypted JSON file hasn't been corrupted

## See Also

- [EXEC-FEATURE.md](./EXEC-FEATURE.md) - Documentation for `vhsm.exec()`
- [QUICKSTART.md](./QUICKSTART.md) - Getting started with vHSM
- [test-app/json-encryption-example.js](./test-app/json-encryption-example.js) - Complete example

