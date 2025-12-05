# VHSM Debug Mode

## Overview

The `VHSM_DEBUG` environment variable controls logging verbosity in vHSM operations. By default, vHSM operates silently (only showing errors), but you can enable detailed logging for troubleshooting.

## Usage

### Enable Debug Mode

```bash
# Linux/macOS
export VHSM_DEBUG=true

# Windows PowerShell
$env:VHSM_DEBUG="true"

# Windows CMD
set VHSM_DEBUG=true
```

### Run Commands with Debug Output

```bash
# CLI
VHSM_DEBUG=true vhsm encrypt config.json
VHSM_DEBUG=true vhsm decrypt config.encrypted.json

# Node.js
VHSM_DEBUG=true node your-script.js
```

## What Gets Logged

### JSON Encryption (Debug Mode ON)

```
🔐 Encrypting JSON file: config.json
   Provider: password
   Output: config.encrypted.json
   Env key: CONFIG_JSON
🔑 Running dotenvx encrypt...
✅ JSON content encrypted
✅ Created encrypted JSON: config.encrypted.json
✅ Updated .env.config.json with reference
✅ Added VHSM_PRIVATE_KEY_CONFIG_JSON to .env.keys.encrypted
✅ Deleted temporary keys file

✅ JSON file encrypted successfully!
   Encrypted file: config.encrypted.json
   Env reference: .env.config.json
```

### JSON Encryption (Debug Mode OFF - Default)

```
(silent - only errors are shown)
```

## Debug Output Includes

When `VHSM_DEBUG=true`, you'll see:

### During Encryption
- Input/output file paths
- Provider being used
- Environment key names
- Each step of the encryption process
- File creation confirmations
- Cleanup operations
- Success/completion messages

### During Decryption
- File paths being accessed
- Keys being decrypted
- Provider information
- Any intermediate operations

### During exec()
- Automatic env file inference (if applicable)
- Parameter processing details
- JSON file loading operations

## When to Use Debug Mode

### ✅ Use Debug Mode When:
- Troubleshooting encryption/decryption issues
- Verifying file paths and key names
- Understanding the encryption flow
- Debugging automation scripts
- Learning how vHSM works
- Reporting issues

### ❌ Don't Use Debug Mode When:
- Running in production (performance overhead)
- In automated CI/CD pipelines (noisy logs)
- When logs might be exposed (security concern)
- Running tests (unless debugging specific test failures)

## Programmatic Usage

You can set the environment variable before running your Node.js script:

```javascript
// Set debug mode programmatically (must be done before importing vhsm)
process.env.VHSM_DEBUG = 'true';

import { encryptJsonFile } from 'vhsm';

await encryptJsonFile('./config.json', {
  provider: 'password',
  password: 'my-password',
});
```

**Note**: Setting it programmatically only works if done before the vHSM module is loaded.

## Example: Debugging a Test

```javascript
// test-json-encryption.js
import { encryptJsonFile, loadFile } from 'vhsm';

async function test() {
  if (process.env.VHSM_DEBUG === 'true') {
    console.log('📝 Debug mode enabled\n');
  }
  
  // Your test code here
  await encryptJsonFile('./test.json', {
    provider: 'password',
    password: 'test-password',
  });
}

test();
```

Run with:
```bash
VHSM_DEBUG=true node test-json-encryption.js
```

## Implementation Details

The debug check is simple:
```typescript
const isDebug = process.env.VHSM_DEBUG === 'true';

if (isDebug) {
  console.log('Debug information...');
}
```

This means:
- Only the exact string `"true"` enables debug mode
- Any other value (including `"1"`, `"yes"`, etc.) is treated as disabled
- Undefined (not set) is treated as disabled

## Affected Operations

Debug mode currently affects:
- ✅ JSON file encryption (`encryptJsonFile`)
- ✅ JSON file decryption (`loadFile`)
- ⚠️ Standard .env encryption/decryption (handled by dotenvx)

For dotenvx operations, use dotenvx's own debug/verbose flags.

## Performance Impact

Debug logging has minimal performance impact:
- String concatenation only happens when debug is enabled
- No file I/O overhead
- Console.log is fast for small amounts of output

However, for production systems processing many files, it's recommended to keep debug mode off to avoid log clutter.

## Future Enhancements

Potential future additions:
- Log levels (TRACE, DEBUG, INFO, WARN, ERROR)
- Log to file instead of console
- Structured logging (JSON format)
- Per-operation debug flags
- Integration with logging frameworks

## See Also

- [JSON-ENCRYPTION.md](./JSON-ENCRYPTION.md) - JSON encryption feature docs
- [EXEC-FEATURE.md](./EXEC-FEATURE.md) - exec() function documentation
- [README.md](./README.md) - Main project documentation


