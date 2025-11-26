FROM node:20-slim

# Install TPM2 tools and dependencies
# For Debian/Ubuntu, the packages are:
# - tpm2-tools: TPM 2.0 utilities
# - tpm2-abrmd: TPM2 Access Broker & Resource Management Daemon
# - libtss2-dev: TPM2 Software stack development libraries
RUN apt-get update && apt-get install -y \
    tpm2-tools \
    tpm2-abrmd \
    libtss2-dev \
    udev \
    && rm -rf /var/lib/apt/lists/*

# Install vhsm globally from npm
RUN npm install -g vhsm

# Copy test-app files
WORKDIR /app/test-app
COPY test-app/package*.json ./
RUN npm install

# Copy test-app source files
COPY test-app/ ./

# Set up TPM2 service (for software TPM simulation)
# Note: For real hardware TPM, you'll need to mount /dev/tpm0
ENV TPM2TOOLS_TCTI="swtpm:path=/tmp/tpm"

# Default command
CMD ["node", "server.js"]

