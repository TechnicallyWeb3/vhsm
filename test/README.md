# VHSM Test Suite

This directory contains comprehensive tests for the vhsm CLI and functionality.

## Test Structure

- `simple-operations.test.ts` - Tests for basic encrypt, decrypt, set, and get operations
- `multi-file-operations.test.ts` - Tests for complex multi-file commands
- `key-flags.test.ts` - Tests for key and excluded-key flags
- `providers.test.ts` - Tests for all providers (password, dpapi, fido2, tpm2)
- `cache.test.ts` - Tests for cache settings and behavior
- `exec.test.ts` - Tests for exec function and allowExec blockers
- `utils/test-helpers.ts` - Test utilities and helpers

## Running Tests

### Run all tests
```bash
npm test
```

### Run tests in watch mode
```bash
npm run test:watch
```

### Run specific test file
```bash
npm run test:compile
npx mocha test-dist/simple-operations.test.js
```

## Test Requirements

- Node.js >= 18.0.0
- @dotenvx/dotenvx must be installed (as a dependency)
- Tests create temporary directories in `test-temp/` which are cleaned up after each test
- Some provider tests (DPAPI, FIDO2, TPM2) may be skipped if the provider is not available on the system

## Test Coverage

The test suite covers:

1. **Simple Operations**
   - Encrypt/decrypt operations
   - Set/get operations
   - Run command execution

2. **Multi-File Operations**
   - Multiple .env files
   - Custom encrypted keys file paths
   - Environment variable injection

3. **Key Flags**
   - `-k` flag for specifying keys
   - `-ek` flag for excluding keys

4. **Providers**
   - Password provider (always available)
   - DPAPI provider (Windows only)
   - TPM2 provider (when available)
   - FIDO2 provider (when available)
   - Provider validation and mismatch detection

5. **Cache Settings**
   - Cache enabled/disabled
   - Cache timeout
   - Clear cache command

6. **Exec Function**
   - allowExec blocker
   - Environment variable injection with @vhsm prefix
   - Nested exec calls
   - Error handling and sensitive data cleanup

## Notes

- Tests are compiled from TypeScript to JavaScript before running
- Test output directory is `test-dist/` (gitignored)
- Temporary test files are created in `test-temp/` (gitignored)
- Tests require the main project to be built (`npm run build`) before running

