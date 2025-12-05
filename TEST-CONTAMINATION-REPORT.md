# Test Contamination Report: JSON File Encryption

## Issue Summary

During testing of the JSON encryption feature, we discovered a test contamination issue where tests using the same filename (`config.json`) were interfering with each other, causing one test to read encrypted data from a previous test.

## Root Cause

### Test Environment Setup
- All tests in the `JSON File Encryption` suite shared the same test directory: `test-temp/json-encryption`
- Each test creates files like `config.json`, encrypts them, and creates `config.encrypted.json` and `.env.config.json`
- When multiple tests use the same filename, the second test's encryption overwrites the first test's files
- However, if cleanup doesn't happen properly or if there's a race condition, stale files can persist

### Specific Failure Case
1. **Test 1**: Creates `config.json` with `{ apiKey: 'secret-key' }` → encrypts → creates `config.encrypted.json`
2. **Test 3**: Creates `config.json` with `{ apiKey: 'key1' }` → encrypts → should overwrite `config.encrypted.json`
3. **Problem**: Test 3 reads the old `config.encrypted.json` from Test 1, getting `apiKey: 'secret-key'` instead of `apiKey: 'key1'`

## Real-World Implications

### How This Could Happen in Production

1. **File System Race Conditions**
   - Multiple processes encrypting the same file simultaneously
   - One process reads while another is writing
   - Result: Stale encrypted file is read

2. **Incomplete Cleanup**
   - Old encrypted files not deleted after re-encryption
   - `.env.config.json` points to old encrypted file
   - Result: Application reads outdated data

3. **Deployment Scenarios**
   - Rolling deployments where old and new encrypted files coexist
   - Configuration updates that don't clean up old files
   - Result: Inconsistent data across instances

4. **Development Workflows**
   - Multiple developers working on the same project
   - Shared test environments
   - Result: Tests fail intermittently

## Solutions Implemented

### 1. Test Isolation Improvements

**Before:**
```typescript
beforeEach(() => {
  env = createTestEnvironment('json-encryption'); // All tests share same dir
});
```

**After:**
```typescript
beforeEach(function() {
  // Unique directory per test
  const testId = `${this.currentTest?.title || 'test'}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const safeTestId = testId.replace(/[^a-zA-Z0-9-_]/g, '_');
  env = createTestEnvironment(`json-encryption-${safeTestId}`);
});
```

**Benefits:**
- Each test gets its own isolated directory
- No file conflicts between tests
- Tests can run in parallel safely
- Cleanup is more reliable

### 2. Code Robustness Improvements

Added validation to ensure encrypted files exist:

```typescript
// Validate that the encrypted file exists
if (!existsSync(jsonFilePath)) {
  throw new Error(
    `Encrypted JSON file not found: ${jsonFilePath} (referenced in ${resolvedJsonEnvFile}). ` +
    `This may indicate the encrypted file was moved or deleted.`
  );
}
```

**Benefits:**
- Fails fast with clear error message
- Prevents silent failures
- Helps identify configuration issues early

## Best Practices for Real Environments

### 1. Use Unique Filenames

**Avoid:**
```bash
# Multiple services using same filename
service1/config.json
service2/config.json
```

**Prefer:**
```bash
# Unique, descriptive filenames
service1-config.json
service2-config.json
api-config.json
db-config.json
```

### 2. Implement File Versioning

For files that need to be updated frequently:

```bash
config.v1.encrypted.json
config.v2.encrypted.json
```

Update `.env.config.json` to point to the new version:
```
CONFIG_JSON=config.v2.encrypted.json
```

### 3. Atomic Updates

When updating encrypted files:

1. Create new encrypted file with temporary name
2. Verify it's valid
3. Update `.env.config.json` atomically
4. Delete old encrypted file
5. Rename temp file to final name

### 4. Validation Checks

Add validation in your application:

```typescript
// Check file modification time
const encryptedFileStat = statSync(jsonFilePath);
const envFileStat = statSync(resolvedJsonEnvFile);

if (encryptedFileStat.mtime < envFileStat.mtime) {
  console.warn('Encrypted file is older than env file - may be stale');
}
```

### 5. Cleanup Scripts

Create cleanup scripts for development:

```bash
#!/bin/bash
# cleanup-encrypted-json.sh
# Remove all encrypted JSON files and their env references

find . -name "*.encrypted.json" -delete
find . -name ".env.*.json" -delete
```

### 6. CI/CD Considerations

In CI/CD pipelines:

- Use isolated workspaces per build
- Clean up between test runs
- Use unique identifiers for test files
- Consider using Docker containers for complete isolation

## Detection and Prevention

### How to Detect This Issue

1. **Intermittent Test Failures**
   - Tests pass in isolation but fail when run together
   - Different results on different runs
   - Flaky test behavior

2. **Stale Data Symptoms**
   - Application reads old configuration values
   - Changes to JSON files don't take effect
   - Unexpected behavior after updates

3. **File System Checks**
   ```bash
   # Check for multiple encrypted files
   ls -la *.encrypted.json
   
   # Check .env file references
   cat .env.config.json
   
   # Verify file timestamps
   stat config.encrypted.json
   stat .env.config.json
   ```

### Prevention Checklist

- [ ] Use unique filenames for each encrypted JSON file
- [ ] Implement proper cleanup in test suites
- [ ] Add file existence validation in code
- [ ] Use atomic file operations
- [ ] Implement file versioning for updates
- [ ] Add monitoring/logging for file operations
- [ ] Document file naming conventions
- [ ] Use isolated test environments
- [ ] Add integration tests that verify file updates

## Recommendations

### For Development
1. **Always use unique test directories** - Never share test directories between tests
2. **Clean up after tests** - Ensure `afterEach` properly removes all created files
3. **Use descriptive filenames** - Avoid generic names like `config.json` in tests
4. **Add file validation** - Check that files exist and are valid before using them

### For Production
1. **Use unique filenames** - Each service/config should have a unique name
2. **Implement atomic updates** - Use temporary files and atomic renames
3. **Add monitoring** - Log file operations and detect stale files
4. **Version control** - Keep track of which encrypted files are in use
5. **Documentation** - Document the file naming and update process

### For CI/CD
1. **Isolated workspaces** - Each build gets a fresh workspace
2. **Parallel test execution** - Use unique directories per test
3. **Cleanup between runs** - Ensure no files persist between builds
4. **Artifact management** - Properly manage encrypted files as artifacts

## Code Changes Summary

### Files Modified

1. **`test/json-encryption.test.ts`**
   - Added unique test directory per test
   - Improved test isolation

2. **`src/exec.ts`**
   - Added file existence validation
   - Better error messages for missing files

### Testing

All tests now pass consistently:
- ✅ 19 passing tests
- ✅ No cross-contamination
- ✅ Proper cleanup between tests

## Conclusion

The test contamination issue was caused by shared test directories. By implementing unique test directories per test and adding file validation, we've:

1. **Fixed the immediate issue** - Tests no longer interfere with each other
2. **Improved code robustness** - Better error handling and validation
3. **Documented best practices** - Clear guidelines for avoiding this in production

The solution is production-ready and follows best practices for file handling and test isolation.

