# JSON Encryption Feature - Implementation Summary

## Feature Overview

The JSON encryption feature has been successfully implemented for vHSM. It allows users to encrypt entire JSON configuration files and access their values securely using the same pattern as environment variables.

## File Pattern

When you encrypt `test.json`, the following files are created:

1. **`test.encrypted.json`** - The encrypted JSON file containing:
   ```json
   {
     "encryptedBy": "vhsm",
     "version": "0.1.13",
     "encryptedValue": "encrypted:..."
   }
   ```

2. **`.env.test.json`** - Reference file containing:
   ```
   TEST_JSON=test.encrypted.json
   ```

3. **`.env.keys.encrypted`** - Encrypted private key:
   ```
   VHSM_PRIVATE_KEY_TEST_JSON=password:...
   ```

## Usage Pattern

### CLI Usage

```bash
# Encrypt a JSON file
vhsm encrypt config.json

# Decrypt a JSON file
vhsm decrypt config.encrypted.json
```

### Programmatic Usage

```typescript
import { encryptJsonFile, loadFile, getJsonValue } from 'vhsm';

// Encrypt a JSON file
await encryptJsonFile('./config.json', {
  provider: 'password',
  password: 'my-password',
  deleteOriginal: false,
});

// Load entire JSON file
const config = await loadFile('./config.encrypted.json', {
  password: 'my-password',
});

// Get specific value using dot notation
const userName = await getJsonValue(
  './config.encrypted.json',
  'user.name',
  { password: 'my-password' }
);
```

### Using in exec()

The key feature is the `@vhsm` syntax that works just like regular environment variables:

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ fullConfig, userName, apiKey }) => {
    // fullConfig contains the entire JSON object
    // userName and apiKey are specific extracted values
    console.log(`User: ${userName}, API: ${apiKey}`);
    return { fullConfig, userName, apiKey };
  },
  {
    // Load entire JSON file
    fullConfig: '@vhsm TEST_JSON',
    
    // Load specific values using dot notation
    userName: '@vhsm TEST_JSON user.name',
    apiKey: '@vhsm TEST_JSON apiKeys.primary',
  },
  {
    password: 'my-password',
    allowExec: true,
  }
);
```

## Key Naming Convention

- **Environment Variable**: `TEST_JSON` (derived from filename `test.json`)
- **DOTENV Private Key**: `DOTENV_PRIVATE_KEY_TEST_JSON` (temporary, deleted by vhsm)
- **VHSM Private Key**: `VHSM_PRIVATE_KEY_TEST_JSON` (stored in `.env.keys.encrypted`)

## How It Works

### Encryption Process:

1. Read JSON file and validate
2. Convert JSON to single-line format (to work with .env format)
3. Create `.env.[filename].json` with `KEY_NAME={json content}`
4. Run `dotenvx encrypt` to encrypt the content and generate `DOTENV_PRIVATE_KEY_KEY_NAME`
5. Extract encrypted value and save to `[filename].encrypted.json`
6. Update `.env.[filename].json` to contain reference: `KEY_NAME=[filename].encrypted.json`
7. Encrypt the DOTENV_PRIVATE_KEY with vHSM provider → `VHSM_PRIVATE_KEY_KEY_NAME`
8. Delete temporary `.env.keys.[filename].json` file
9. Optionally delete original JSON file

### Decryption Process:

1. Read `[filename].encrypted.json` to get encrypted value
2. Find and decrypt `VHSM_PRIVATE_KEY_KEY_NAME` to get `DOTENV_PRIVATE_KEY_KEY_NAME`
3. Temporarily update `.env.[filename].json` to contain `KEY_NAME=encrypted:...`
4. Use dotenvx to decrypt the value (it finds the key in process.env)
5. Parse the decrypted JSON
6. Restore `.env.[filename].json` to contain the reference
7. Return the JSON object or specific value

## Implementation Files

- **`src/lib/files.ts`** - Core encryption/decryption logic
- **`src/exec.ts`** - Integration with `exec()` function
- **`src/index.ts`** - Exports for public API
- **`src/cli/vhsm.ts`** - CLI commands
- **`test-json-encryption.js`** - Test suite
- **`test-app/json-encryption-example.js`** - Comprehensive example
- **`JSON-ENCRYPTION.md`** - User documentation

## Features Implemented

✅ Encrypt JSON files via CLI and programmatically  
✅ Decrypt JSON files via CLI and programmatically  
✅ Load entire JSON files in code  
✅ Access specific JSON values using dot notation  
✅ Use JSON values in `exec()` with `@vhsm KEY_NAME` syntax  
✅ Use JSON dot notation in `exec()` with `@vhsm KEY_NAME path.to.value` syntax  
✅ Support all vHSM providers (password, dpapi, fido2, tpm2)  
✅ Session caching for performance  
✅ Automatic memory cleanup  
✅ --no-delete option to keep original files  

## Testing

Run the test:
```bash
node test-json-encryption.js
```

All tests pass successfully:
- ✅ Encryption
- ✅ Loading entire JSON file
- ✅ Dot notation access
- ✅ Memory cleanup

## Next Steps

The feature is complete and ready for use. Documentation has been created in:
- `JSON-ENCRYPTION.md` - Complete user guide
- `README.md` - Updated with JSON encryption section
- `test-app/json-encryption-example.js` - Working examples

