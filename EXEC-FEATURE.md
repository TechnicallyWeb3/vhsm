# vhsm.exec() - Secure Function Execution Feature

## Overview

The `vhsm.exec()` function is a powerful feature that allows you to execute functions with automatic decryption and injection of environment variables. This enables you to securely use encrypted environment variables in your code without exposing them to memory longer than necessary.

**⚠️ Security Note**: `vhsm.exec()` is **disabled by default** for security. You must explicitly enable it via:
- Environment variable: `VHSM_ALLOW_EXEC=true`
- Config file: Add `"allowExec": true` to `.vhsmrc.json`
- Per-execution: Pass `allowExec: true` in options

## Features

- ✅ Automatic decryption of vHSM-encrypted dotenvx keys
- ✅ Environment variable injection using `"@vhsm KEY"` syntax
- ✅ Automatic memory cleanup of sensitive data
- ✅ Support for mixed parameters (env vars + regular values)
- ✅ Session caching for improved performance
- ✅ Support for multiple env files (.env, .env.local, etc.)

## Usage

### Basic Example

```typescript
import { exec } from 'vhsm';

// Define your function
async function signMessage({ message, nonce, apiKey }) {
  // Use the apiKey which was automatically decrypted from .env
  return signWithKey(message, nonce, apiKey);
}

// Execute with automatic env variable injection
const result = await exec(
  signMessage,
  {
    message: 'Hello, World!',
    nonce: '123456',
    apiKey: '@vhsm API_KEY'  // This will be decrypted from .env
  },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    envFile: '.env'
  }
);
```

### How It Works

1. **Parameter Processing**: When `vhsm.exec()` encounters a parameter value starting with `"@vhsm "`, it:
   - Extracts the environment variable name (e.g., `"API_KEY"` from `"@vhsm API_KEY"`)
   - Decrypts the vHSM-encrypted dotenvx private key
   - Uses dotenvx to decrypt and retrieve the environment variable from your `.env` file
   - Replaces the `"@vhsm KEY"` placeholder with the actual decrypted value

2. **Function Execution**: The function is executed with the processed parameters

3. **Memory Cleanup**: Immediately after execution, all sensitive values are cleared from memory

### Options

```typescript
interface ExecOptions {
  /**
   * Path to encrypted private key file
   * @default '.env.keys.encrypted'
   */
  encryptedKeysFile?: string;
  
  /**
   * Path to .env file
   * @default '.env'
   */
  envFile?: string;
  
  /**
   * Provider name to use for decryption
   * If not provided, will use the provider specified in the encrypted key file
   */
  provider?: string;
  
  /**
   * Password/passphrase for decryption (for password provider)
   */
  password?: string;
  
  /**
   * Whether to enable session caching
   * @default true
   */
  enableCache?: boolean;
  
  /**
   * Cache timeout in milliseconds
   * @default 3600000 (1 hour)
   */
  cacheTimeout?: number;
  
  /**
   * Custom path to .env.keys file (for dotenvx)
   */
  envKeysFile?: string;
  
  /**
   * Override the global allowExec setting for this execution
   * If not provided, uses the value from config file or VHSM_ALLOW_EXEC env var
   * Default: false (must be explicitly enabled for security)
   */
  allowExec?: boolean;
}
```

### Security Configuration

`vhsm.exec()` requires explicit opt-in for security. Enable it using one of these methods:

**1. Environment Variable (recommended for CI/CD)**
```bash
export VHSM_ALLOW_EXEC=true
```

**2. Config File (`.vhsmrc.json` in project root or home directory)**
```json
{
  "allowExec": true
}
```

**3. Per-Execution Override**
```typescript
await exec(myFunction, params, { allowExec: true });
```

If `allowExec` is not enabled, `exec()` will throw an error:
```
vhsm.exec() is disabled by default for security. To enable, set VHSM_ALLOW_EXEC=true 
environment variable or add "allowExec": true to your .vhsmrc.json config file.
```

### Examples

#### Example 1: Signing with API Key

```typescript
import { exec } from 'vhsm';

const signedResult = await exec(
  async ({ message, nonce, apiKey }) => {
    // apiKey was automatically decrypted from @vhsm API_KEY
    return crypto.createHmac('sha256', apiKey)
      .update(message + nonce)
      .digest('hex');
  },
  {
    message: 'Hello, World!',
    nonce: '123456789',
    apiKey: '@vhsm API_KEY'
  }
);
```

#### Example 2: Database Query

```typescript
import { exec } from 'vhsm';

const dbResult = await exec(
  async ({ query, databaseUrl }) => {
    // databaseUrl was automatically decrypted from @vhsm DATABASE_URL
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    const result = await client.query(query);
    await client.end();
    return result.rows;
  },
  {
    query: 'SELECT * FROM users LIMIT 10',
    databaseUrl: '@vhsm DATABASE_URL'
  }
);
```

#### Example 3: Mixed Parameters

```typescript
import { exec } from 'vhsm';

const result = await exec(
  async ({ userId, message, apiKey, timestamp }) => {
    // Mix of regular parameters and env variables
    return {
      userId,        // Regular parameter
      message,       // Regular parameter
      apiKey,        // Decrypted from @vhsm API_KEY
      timestamp      // Regular parameter
    };
  },
  {
    userId: 'user123',
    message: 'Hello',
    apiKey: '@vhsm API_KEY',      // Will be decrypted
    timestamp: new Date().toISOString()
  }
);
```

#### Example 4: Using Different Env Files

```typescript
import { exec } from 'vhsm';

// Use .env.local file
const result = await exec(
  myFunction,
  { apiKey: '@vhsm API_KEY' },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    envFile: '.env.local'  // Uses DOTENV_PRIVATE_KEY_LOCAL
  }
);
```

## Security Features

### Automatic Memory Cleanup

All sensitive values are automatically cleared from memory immediately after function execution:

- Decrypted environment variables
- Decrypted private keys
- All values marked with `@vhsm` prefix

### Session Caching

Decrypted keys are cached in memory for a configurable timeout (default: 1 hour) to improve performance while maintaining security.

### No Disk Exposure

Sensitive values never touch the disk in plaintext:
- Keys are only decrypted in memory
- Environment variables are decrypted on-demand
- All values are cleared immediately after use

## Example File

See `test-app/exec-example.js` for a complete working example demonstrating all features.

## Running the Example

```bash
# First, ensure you have encrypted keys set up
cd test-app
vhsm encrypt

# Then run the example
node exec-example.js
```

Or using the vhsm CLI to run it with proper environment:

```bash
vhsm run -f test-app/.env -- node test-app/exec-example.js
```

## API Reference

### `exec<T>(fn, params, options?)`

Execute a function with automatic environment variable injection.

**Parameters:**
- `fn`: The function to execute. Should accept a single object parameter.
- `params`: Object containing parameters for the function. Use `"@vhsm KEY"` for env variables.
- `options`: Optional execution options (see `ExecOptions` above).

**Returns:**
- Promise resolving to the return value of `fn`.

**Throws:**
- Error if environment variable not found
- Error if decryption fails
- Error from the executed function

## Best Practices

1. **Use descriptive parameter names**: Make it clear which parameters contain sensitive data
2. **Minimize exposure time**: The function should use sensitive values quickly and return
3. **Don't log sensitive values**: Avoid logging parameters that contain `@vhsm` values
4. **Use appropriate env files**: Use `.env.local` for local development, `.env.production` for production, etc.
5. **Enable caching in production**: For better performance, keep `enableCache: true` (default)

## Migration Guide

If you're currently using environment variables directly:

**Before:**
```typescript
const apiKey = process.env.API_KEY;
const result = signMessage({ message, nonce, apiKey });
```

**After:**
```typescript
const result = await exec(
  signMessage,
  { message, nonce, apiKey: '@vhsm API_KEY' }
);
```

This approach ensures:
- Keys are never exposed in plaintext
- Memory is cleaned up immediately
- Better security posture overall

