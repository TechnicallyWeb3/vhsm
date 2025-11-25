# Project Structure

```
vhsm/
├── src/
│   ├── cli.ts              # Main CLI entry point
│   ├── index.ts            # Public API exports
│   ├── types.ts            # TypeScript interfaces and types
│   ├── cache.ts            # Session cache implementation
│   ├── config.ts           # Configuration loading
│   ├── security.ts         # Security utilities
│   └── providers/
│       ├── index.ts         # Provider registry
│       ├── password.ts     # Password-based provider (default)
│       └── README.md       # Provider development guide
├── dist/                   # Compiled JavaScript (generated)
├── package.json            # NPM package configuration
├── tsconfig.json           # TypeScript configuration
├── README.md               # Main documentation
├── EXAMPLE.md              # Usage examples
├── LICENSE                 # MIT License
└── .gitignore              # Git ignore rules

```

## Key Components

### Core Modules

- **`cli.ts`**: Command-line interface using Commander.js
  - `run` command: Decrypts key and executes dotenvx
  - `encrypt` command: Encrypts a plaintext key
  - `clear-cache` command: Clears session cache

- **`types.ts`**: Type definitions
  - `KeyDecryptionProvider`: Interface for pluggable providers
  - `VhsmConfig`: Configuration structure
  - `DecryptionError`: Secure error class

- **`cache.ts`**: In-memory session cache
  - Timeout-based expiration
  - Automatic cleanup
  - Key ID-based lookup

- **`config.ts`**: Configuration management
  - File-based config (`.vhsmrc.json`)
  - Environment variable overrides
  - Sensible defaults

- **`security.ts`**: Security utilities
  - Key ID generation
  - Error message sanitization
  - Memory clearing (best effort)

### Providers

- **`providers/index.ts`**: Provider registry
  - Registration system
  - Provider lookup
  - Default provider management

- **`providers/password.ts`**: Password provider
  - AES-256-GCM encryption
  - PBKDF2 key derivation
  - Interactive password prompt

## Extension Points

### Adding New Providers

1. Create provider class implementing `KeyDecryptionProvider`
2. Register in `providers/index.ts`
3. Document in `src/providers/README.md`

### Configuration

- File: `.vhsmrc.json` or `.vhsm.json`
- Environment: `VHSM_*` variables
- CLI: Command-line flags override all

### Security Model

- Keys never written to disk (except encrypted)
- Decrypted keys only in process memory
- Session cache with automatic expiration
- Error messages sanitized
- Secure file permissions (600)

## Build Process

```bash
npm install    # Install dependencies
npm run build  # Compile TypeScript to dist/
npm start      # Run CLI (after build)
```

## Distribution

The `dist/` directory contains:
- Compiled JavaScript (`.js`)
- Type definitions (`.d.ts`)
- Source maps (`.js.map`, `.d.ts.map`)

Only `dist/` and configuration files are published to npm.

