# vhsm Usage Examples

## Basic Workflow

### 1. Initial Setup

First, generate or obtain your dotenvx private key. If you don't have one:

```bash
# Generate a new dotenvx key (if needed)
dotenvx encrypt
```

This creates `.env.keys` in your project.

### 2. Encrypt the Key

Pick the provider that matches your workflow:

```bash
# Password (default, works everywhere)
vhsm encrypt

# Windows DPAPI (machine/user bound)
vhsm encrypt -p dpapi

# FIDO2 (hardware-backed - Windows Hello, security keys, mobile)
vhsm encrypt -p fido2

# Custom paths still work with any provider
vhsm encrypt -p fido2 -fk .env.secure -o .env.vhsm
```

- **password** prompts for an 8+ character passphrase.
- **dpapi** never prompts and ties secrets to your Windows account.
- **fido2** launches a browser flow for FIDO2 authentication (Windows Hello, security keys, mobile - credential is reused for multiple keys).

All providers output `VHSM_PRIVATE_KEY=<provider>:...` lines to `.env.keys.encrypted` (mode 600). Delete `.env.keys` unless passing `-nd`.

### 3. Use vhsm to Run Commands

Replace `dotenvx run` with `vhsm run`:

```bash
# Before (insecure - key in plaintext)
dotenvx run npm start

# After (secure - key encrypted, decrypted at runtime)
vhsm run -- npm start    # Provider auto-detected
```

### 4. Add to .gitignore

Ensure encrypted keys are never committed:

```bash
echo ".env.keys.encrypted" >> .gitignore
echo ".env.keys" >> .gitignore  # Also ignore plaintext keys
```

### 5. Restore Keys When Needed

If you need to restore the `.env.keys` file from the encrypted version:

```bash
vhsm decrypt --restore
# or with custom paths
vhsm decrypt -ef .env.vhsm -r -fk .env.secure
```

## Advanced Usage

### Custom Key Path

```bash
vhsm run -ef .secrets/dotenvx.key.encrypted -- npm start
```

### Disable Caching

For maximum security, disable session caching:

```bash
vhsm run --no-cache -- npm start
# or
vhsm run -nc -- npm start
```

### Custom Cache Timeout

Set cache to expire after 30 minutes:

```bash
vhsm run --cache-timeout 1800000 -- npm start
# or
vhsm run -ct 1800000 -- npm start
```

### Running Complex Commands

```bash
vhsm run -- npm test --coverage
vhsm run -- node server.js --port 3000
vhsm run -- python manage.py runserver
```

### Using with npm scripts

Update your `package.json`:

```json
{
  "scripts": {
    "start": "vhsm run -- node server.js",
    "dev": "vhsm run -- nodemon server.js",
    "test": "vhsm run -- jest"
  }
}
```

Then run:

```bash
npm start
npm run dev
npm test
```

## Configuration Examples

### Project-Level Configuration

Create `.vhsmrc.json`:

```json
{
  "provider": "password",
  "cacheTimeout": 1800000,
  "enableCache": true
}
```

### Environment Variables

```bash
export VHSM_PROVIDER=password
export VHSM_CACHE_TIMEOUT=3600000
export VHSM_ENABLE_CACHE=true

vhsm run npm start
```

### Per-Command Override

```bash
# Use config file defaults
vhsm run npm start

# Override cache timeout for this command
vhsm run -ct 600000 -- npm start

# Disable cache for this command
vhsm run -nc npm start

# Use custom encrypted key file
vhsm run -ef custom/path/.env.keys.encrypted -- npm start
```

## Security Scenarios

### Team Development

1. **Share encrypted key securely**:
   - Use a secure secret sharing service (1Password, Bitwarden, etc.)
   - Or use encrypted communication channels
   - Never commit to version control

2. **Each developer encrypts with their own passphrase**:
   ```bash
   # Developer A
   vhsm encrypt -o .env.keys.encrypted
   
   # Developer B (with their own passphrase)
   vhsm encrypt -o .env.keys.encrypted
   ```

3. **Or use a shared team passphrase** (stored in password manager)

4. **Restore keys for new team members**:
   ```bash
   # New team member receives encrypted key and passphrase
   vhsm decrypt -r -ef .env.keys.encrypted
   ```

### CI/CD Integration

For CI/CD, use environment variables or secret management:

```bash
# In CI, set decrypted key directly (from secure vault)
export DOTENV_PRIVATE_KEY="$(vault read -field=key secret/dotenvx)"
dotenvx run npm test
```

vhsm is designed for local development. In CI/CD, use your platform's secret management.

### Multiple Environments

Use different encrypted keys for different environments:

```bash
# Development
vhsm encrypt -fk .env.keys.dev -o .env.keys.dev.encrypted

# Staging
vhsm encrypt -fk .env.keys.staging -o .env.keys.staging.encrypted

# Production (use proper secret management, not vhsm)
```

### Using dotenvx Pass-Through Options

```bash
# Encrypt specific keys only
vhsm encrypt -k DATABASE_URL API_KEY

# Exclude specific keys from encryption
vhsm encrypt -ek DATABASE_URL

# Encrypt specific env files
vhsm encrypt -f .env.production .env.staging

# Decrypt specific keys
vhsm decrypt -k DATABASE_URL API_KEY

# Decrypt specific env files
vhsm decrypt -f .env.production
```

## Troubleshooting Examples

### Key File Not Found

```bash
# Check if file exists
ls -la .env.keys.encrypted

# Use custom path
vhsm run -ef /path/to/key.encrypted -- npm start
```

### Wrong Passphrase

```bash
# Clear cache and retry
vhsm clear-cache
vhsm run npm start
```

### dotenvx Not Found

```bash
# Install dotenvx globally
npm install -g @dotenvx/dotenvx

# Or use npx
vhsm run -- npm start  # vhsm already includes dotenvx, no need to call it separately
# Better: vhsm includes dotenvx, no PATH needed
```

## Integration Examples

### With Docker

```dockerfile
# Dockerfile
FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["vhsm", "run", "npm", "start"]
```

Note: For Docker, consider implementing a `docker-secrets` provider instead.

### With Make

```makefile
.PHONY: start
start:
	vhsm run npm start

.PHONY: test
test:
	vhsm run -- npm test
```

### With Shell Scripts

```bash
#!/bin/bash
# deploy.sh
vhsm run npm run build
vhsm run npm run deploy
```

