# Automatic envFile Inference for JSON Keys

## Feature

The `exec()` function now automatically infers the correct `.env.[filename].json` file from JSON key names ending with `_JSON`. This eliminates the need to manually specify the `envFile` parameter when working with encrypted JSON files.

## How It Works

When you use `@vhsm KEY_NAME_JSON` in exec(), the system automatically:

1. Detects that the key ends with `_JSON`
2. Converts the key name to the corresponding env file:
   - `CONFIG_JSON` → `.env.config.json`
   - `DB_JSON` → `.env.db.json`
   - `SECRETS_JSON` → `.env.secrets.json`
3. Uses that file for loading the encrypted data

## Usage Examples

### Before (Manual envFile)

```typescript
const result = await exec(
  async ({ config }) => {
    return config;
  },
  {
    config: '@vhsm CONFIG_JSON',
  },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    envFile: '.env.config.json',  // Had to specify manually
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

### After (Automatic Inference)

```typescript
const result = await exec(
  async ({ config }) => {
    return config;
  },
  {
    config: '@vhsm CONFIG_JSON',
  },
  {
    encryptedKeysFile: '.env.keys.encrypted',
    // envFile is automatically inferred!
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

## Multiple JSON Files

When using multiple JSON files, the system uses the first `_JSON` key it finds:

```typescript
const result = await exec(
  async ({ apiKey, dbPassword }) => {
    return { apiKey, dbPassword };
  },
  {
    apiKey: '@vhsm CONFIG_JSON apiKey',
    dbPassword: '@vhsm SECRETS_JSON dbPassword',
  },
  {
    // Uses .env.config.json (first key with _JSON suffix)
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

**Note**: All JSON values must be encrypted with the same `.env` file's key for this to work correctly. If you need different keys, you'll need to make separate `exec()` calls.

## Override Behavior

You can still manually specify the `envFile` if needed:

```typescript
const result = await exec(
  async ({ config }) => {
    return config;
  },
  {
    config: '@vhsm CONFIG_JSON',
  },
  {
    envFile: './custom/path/.env.config.json',  // Manual override
  }
);
// Note: Requires VHSM_ALLOW_EXEC=true environment variable
```

## Benefits

1. **Cleaner Code** - No need to repeat the file path when it's already encoded in the key name
2. **Less Error-Prone** - No chance of mismatching the key name and env file
3. **Consistent Pattern** - Follows the established naming convention
4. **Backward Compatible** - Manual `envFile` still works if needed

## Key Naming Convention

To use automatic inference, your keys must follow this pattern:

- End with `_JSON` suffix
- Example: `CONFIG_JSON`, `DATABASE_JSON`, `SETTINGS_JSON`

The corresponding env file will be:
- Remove `_JSON` suffix
- Convert to lowercase
- Prepend `.env.` and append `.json`

Examples:
- `CONFIG_JSON` → `.env.config.json`
- `DATABASE_JSON` → `.env.database.json`
- `MY_SETTINGS_JSON` → `.env.my_settings.json`

## Implementation Details

The inference happens in the `processParams()` function of `exec()`:

1. It scans all parameters for `@vhsm` prefixed values
2. Extracts the key name (e.g., `CONFIG_JSON`)
3. Checks if it ends with `_JSON`
4. If yes, generates the env file path: `.env.{lowercase(key_without_json)}.json`
5. Uses that as the `envFile` for decryption

This happens before any decryption, so the correct key is loaded for all operations.


