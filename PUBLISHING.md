# Publishing vHSM to npm

This guide will walk you through publishing vHSM to npm.

## Prerequisites

1. **npm Account**: Create one at https://www.npmjs.com/signup if you don't have one
2. **Verified Email**: Make sure your npm email is verified
3. **Two-Factor Authentication**: Highly recommended for security

## Pre-Publishing Checklist

### ✅ 1. Update Version Number

Edit `package.json` and update the version following [Semantic Versioning](https://semver.org/):

```bash
# For first release, keep at 0.1.0
# For patches: 0.1.1, 0.1.2, etc.
# For minor features: 0.2.0, 0.3.0, etc.
# For major changes: 1.0.0, 2.0.0, etc.
```

Or use npm:
```bash
npm version patch   # 0.1.0 -> 0.1.1
npm version minor   # 0.1.0 -> 0.2.0
npm version major   # 0.1.0 -> 1.0.0
```

### ✅ 2. Update Repository URL (if needed)

In `package.json`, make sure the repository URL is correct:

```json
"repository": {
  "type": "git",
  "url": "https://github.com/YOUR_USERNAME/vhsm.git"
}
```

Update to your actual GitHub username/org.

### ✅ 3. Ensure README is Complete

Your README.md should include:
- Installation instructions
- Usage examples
- API documentation
- Provider descriptions (password, dpapi, fido2)
- Link to guides

### ✅ 4. Build the Package

```bash
npm run build
```

This compiles TypeScript to the `dist/` folder.

### ✅ 5. Test Locally

Test the package locally before publishing:

```bash
# Pack the package (creates a .tgz file)
npm pack

# This creates: vhsm-0.1.0.tgz
# Install it in a test project:
cd ../test-project
npm install ../vhsm/vhsm-0.1.0.tgz

# Test the CLI
npx vhsm --help
```

### ✅ 6. Check Package Contents

See what will be published:

```bash
npm publish --dry-run
```

This shows you:
- All files that will be included
- Package size
- Any warnings or errors

## Publishing Steps

### Step 1: Login to npm

```bash
npm login
```

Enter your:
- Username
- Password
- Email
- OTP (if 2FA is enabled)

Verify login:
```bash
npm whoami
```

### Step 2: Publish

For first release:

```bash
npm publish
```

For scoped packages (e.g., `@yourorg/vhsm`):

```bash
npm publish --access public
```

### Step 3: Verify Publication

Visit: https://www.npmjs.com/package/vhsm

Check:
- ✅ README displays correctly
- ✅ Version is correct
- ✅ Install command works
- ✅ Links work

### Step 4: Test Installation

In a fresh directory:

```bash
npm install vhsm
npx vhsm --help
```

## Post-Publishing

### Tag the Release in Git

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Create GitHub Release

Go to: https://github.com/YOUR_USERNAME/vhsm/releases

1. Click "Create a new release"
2. Choose tag: v0.1.0
3. Title: "vHSM v0.1.0 - Initial Release"
4. Description:
   ```markdown
   ## Features
   - Password-based encryption
   - Windows DPAPI support
   - FIDO2/Yubikey hardware authentication
   - Session caching
   - Multiple environment file support
   
   ## Installation
   `npm install -g vhsm`
   
   ## Documentation
   - [README](./README.md)
   - [FIDO2 Guide](./FIDO2-GUIDE.md)
   - [Quick Start](./FIDO2-QUICKSTART.md)
   ```

### Announce

- Tweet about it
- Post on Reddit (r/node, r/javascript)
- Share on Discord/Slack communities
- Update personal blog/website

## Updating the Package

When you want to release a new version:

1. Make your changes
2. Update version: `npm version patch` (or minor/major)
3. Build: `npm run build`
4. Publish: `npm publish`
5. Tag: `git tag v0.1.1 && git push origin v0.1.1`
6. Create GitHub release

## Troubleshooting

### Error: 403 Forbidden

**Problem**: Package name is taken or you don't have permission

**Solution**: 
- Choose a different name (e.g., `@yourorg/vhsm`)
- Or claim the package if it's abandoned (contact npm support)

### Error: 402 Payment Required

**Problem**: Trying to publish a scoped package without access

**Solution**: Use `npm publish --access public`

### Error: No README data

**Problem**: README.md is missing or not included

**Solution**: Ensure README.md exists and is in the "files" array

### Package Too Large

**Problem**: Package exceeds size limits

**Solution**: 
- Add `.npmignore` to exclude unnecessary files
- Remove test files, examples, docs from package
- Check with `npm publish --dry-run`

### Wrong Files Published

**Problem**: Test files or source files in published package

**Solution**: Update `files` array in package.json:

```json
"files": [
  "dist/",
  "README.md",
  "LICENSE"
]
```

## .npmignore Example

Create `.npmignore` to exclude files from npm package:

```
# Source files (only dist/ is needed)
src/
*.ts
!*.d.ts

# Tests
test/
test-app/
*.test.js
*.spec.js

# Development files
.vscode/
.github/
.cursor/
*.log
.env*
!.env.example

# Documentation (if you don't want to include)
docs/
examples/

# Build artifacts
tsconfig.json
.tsbuildinfo
```

## Best Practices

1. **Semantic Versioning**: Follow semver strictly
2. **Changelog**: Maintain CHANGELOG.md with version history
3. **Breaking Changes**: Clearly document in major versions
4. **Deprecation Warnings**: Warn users before removing features
5. **Security**: Enable npm 2FA, use `npm audit`
6. **Testing**: Test before every publish
7. **Documentation**: Keep README up to date
8. **License**: Include LICENSE file (MIT is included)

## Useful Commands

```bash
# Check what will be published
npm publish --dry-run

# View package info
npm view vhsm

# View specific version
npm view vhsm@0.1.0

# View all versions
npm view vhsm versions

# Unpublish (within 72 hours, use carefully!)
npm unpublish vhsm@0.1.0

# Deprecate a version (prefer this over unpublish)
npm deprecate vhsm@0.1.0 "Please upgrade to 0.1.1"

# See package download stats
npm info vhsm
```

## Quick Publish Checklist

Before running `npm publish`:

- [ ] Code builds without errors (`npm run build`)
- [ ] Tests pass (if you have them)
- [ ] README is updated
- [ ] Version number is bumped
- [ ] CHANGELOG is updated
- [ ] Repository URL is correct
- [ ] Author field is filled
- [ ] License is specified
- [ ] `.npmignore` or `files` is configured
- [ ] Dry-run looks good (`npm publish --dry-run`)
- [ ] Logged into npm (`npm whoami`)

## Support

- npm docs: https://docs.npmjs.com/
- Semver: https://semver.org/
- npm support: https://www.npmjs.com/support

---

**Ready to publish?** Run:

```bash
npm run build
npm publish --dry-run  # Check first
npm publish            # Publish!
```

🎉 Congratulations on publishing vHSM!

