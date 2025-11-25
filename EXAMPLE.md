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

Encrypt your dotenvx private key with vhsm:

```bash
vhsm encrypt .env.keys -o .env.keys.encrypted
```

You'll be prompted to:
- Enter a passphrase (minimum 8 characters)
- Confirm the passphrase

The encrypted key is saved to `.env.keys.encrypted` with secure permissions (600).

### 3. Use vhsm to Run Commands

Replace `dotenvx run` with `vhsm run`:

```bash
# Before (insecure - key in plaintext)
dotenvx run npm start

# After (secure - key encrypted, decrypted at runtime)
vhsm run npm start
```

### 4. Add to .gitignore

Ensure encrypted keys are never committed:

```bash
echo ".env.keys.encrypted" >> .gitignore
echo ".env.keys" >> .gitignore  # Also ignore plaintext keys
```

## Advanced Usage

### Custom Key Path

```bash
vhsm run -k .secrets/dotenvx.key.encrypted npm start
```

### Disable Caching

For maximum security, disable session caching:

```bash
vhsm run --no-cache npm start
```

### Custom Cache Timeout

Set cache to expire after 30 minutes:

```bash
vhsm run --cache-timeout 1800000 npm start
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
    "start": "vhsm run node server.js",
    "dev": "vhsm run nodemon server.js",
    "test": "vhsm run jest"
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
vhsm run --cache-timeout 600000 npm start

# Disable cache for this command
vhsm run --no-cache npm start
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
   vhsm encrypt .env.keys -o .env.keys.encrypted
   
   # Developer B (with their own passphrase)
   vhsm encrypt .env.keys -o .env.keys.encrypted
   ```

3. **Or use a shared team passphrase** (stored in password manager)

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
vhsm encrypt .env.keys.dev -o .env.keys.dev.encrypted

# Staging
vhsm encrypt .env.keys.staging -o .env.keys.staging.encrypted

# Production (use proper secret management, not vhsm)
```

## Troubleshooting Examples

### Key File Not Found

```bash
# Check if file exists
ls -la .env.keys.encrypted

# Use custom path
vhsm run -k /path/to/key.encrypted npm start
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
vhsm run -- npx dotenvx run npm start  # Note: This won't work as expected
# Better: ensure dotenvx is in PATH
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
	vhsm run npm test
```

### With Shell Scripts

```bash
#!/bin/bash
# deploy.sh
vhsm run npm run build
vhsm run npm run deploy
```

