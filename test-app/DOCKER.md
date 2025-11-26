# Docker Testing with TPM2

This guide explains how to test vhsm with TPM2 using Docker, since `tpm2-tools` is only available on Linux/macOS.

## Prerequisites

- Docker and Docker Compose installed
- For hardware TPM: TPM 2.0 chip in your system
- For software TPM: swtpm (optional, for testing without hardware)

## Quick Start

### Option 1: Using Docker Compose (Recommended)

```bash
# From project root
cd test-app
docker-compose up --build
```

This will:
1. Build a Docker image with Node.js, vhsm, and tpm2-tools
2. Start a container with the test-app
3. Provide an interactive shell

### Option 2: Using Docker Directly

```bash
# Build the image
docker build -f test-app/Dockerfile -t vhsm-test:latest .

# Run with hardware TPM (if available)
docker run -it --rm \
  --device=/dev/tpm0 \
  -v $(pwd)/test-app:/app/test-app \
  vhsm-test:latest bash

# Or run with software TPM simulation
docker run -it --rm \
  -v $(pwd)/test-app:/app/test-app \
  vhsm-test:latest bash
```

## Testing TPM2 Provider

Once inside the container:

```bash
# Navigate to test-app
cd /app/test-app

# Test TPM2 availability
node ../../test-tpm2.js

# If TPM2 is available, encrypt with TPM2
vhsm encrypt -p tpm2 -fk .env.keys -o .env.keys.encrypted

# Run with TPM2 decryption
vhsm run -p tpm2 -ef .env.keys.encrypted -- node server.js
```

## Hardware TPM vs Software TPM

### Hardware TPM (Real TPM Chip)

If your system has a TPM 2.0 chip:

1. **Check if TPM is available:**
   ```bash
   ls -l /dev/tpm0
   ```

2. **Uncomment device mount in docker-compose.yml:**
   ```yaml
   volumes:
     - /dev/tpm0:/dev/tpm0
   ```

3. **Run with device access:**
   ```bash
   docker-compose up
   ```

### Software TPM (swtpm - for testing)

For testing without hardware TPM, you can use swtpm:

1. **Install swtpm (on host):**
   ```bash
   # Linux
   sudo apt install swtpm swtpm-tools
   
   # macOS
   brew install swtpm
   ```

2. **Start swtpm socket:**
   ```bash
   mkdir -p /tmp/myvtpm
   swtpm socket --tpmstate dir=/tmp/myvtpm \
     --tpm2 \
     --ctrl type=unixio,path=/tmp/myvtpm/swtpm-sock \
     --log level=20
   ```

3. **Update docker-compose.yml to use swtpm socket:**
   ```yaml
   volumes:
     - /tmp/myvtpm:/tmp/myvtpm
   environment:
     - TPM2TOOLS_TCTI=swtpm:path=/tmp/myvtpm/swtpm-sock
   ```

## Troubleshooting

### "TPM2 tools not found"

The container should have tpm2-tools installed. If you see this error:

```bash
# Check if tpm2-tools is installed
which tpm2_getrandom

# If not found, install manually
apt-get update && apt-get install -y tpm2-tools
```

### "No TPM device found"

If using hardware TPM:

1. **Check TPM device exists:**
   ```bash
   ls -l /dev/tpm*
   ```

2. **Check permissions:**
   ```bash
   # Add user to tss group (if needed)
   usermod -aG tss $USER
   ```

3. **Verify TPM is accessible:**
   ```bash
   tpm2_getrandom 4
   ```

### "Permission denied" on /dev/tpm0

The container needs access to the TPM device:

```bash
# Run with privileged mode (less secure)
docker run --privileged ...

# Or add specific device with proper permissions
docker run --device=/dev/tpm0 ...
```

## Uninstalling

To remove the Docker setup:

```bash
# Stop and remove containers
docker-compose down

# Remove the image
docker rmi vhsm-test:latest

# Remove volumes (if any)
docker volume prune
```

## Notes

- **Windows Users**: Docker Desktop on Windows can access TPM if:
  - WSL2 is enabled
  - TPM passthrough is configured in Docker Desktop settings
  - Or use WSL2 directly with Linux distribution

- **macOS Users**: Docker Desktop on macOS cannot access hardware TPM. Use swtpm for testing.

- **Linux Users**: Native TPM access works best. Docker is mainly for isolated testing.

## Example Workflow

```bash
# 1. Start container
docker-compose up -d

# 2. Enter container
docker-compose exec vhsm-test bash

# 3. Inside container - test TPM2
cd /app/test-app
node ../../test-tpm2.js

# 4. Encrypt with TPM2
vhsm encrypt -p tpm2 -fk .env.keys -o .env.keys.encrypted

# 5. Run application
vhsm run -p tpm2 -ef .env.keys.encrypted -- node server.js

# 6. Exit and stop
exit
docker-compose down
```

