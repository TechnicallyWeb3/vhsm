#!/bin/bash

# Setup script for vhsm test app
# Run this from the project root

set -e

echo "🔧 Setting up vhsm test application..."
echo ""

# Check if dotenvx is installed
if ! command -v dotenvx &> /dev/null; then
    echo "❌ dotenvx not found. Installing..."
    npm install -g @dotenvx/dotenvx
fi

# Check if vhsm is built
if [ ! -f "dist/cli.js" ]; then
    echo "❌ vhsm not built. Building..."
    npm run build
fi

cd test-app

# Install test app dependencies
echo "📦 Installing test app dependencies..."
npm install

# Generate dotenvx key if it doesn't exist
if [ ! -f ".env.keys" ]; then
    echo "🔑 Generating dotenvx private key..."
    dotenvx encrypt
else
    echo "✅ dotenvx key already exists"
fi

# Encrypt the key if encrypted version doesn't exist
if [ ! -f ".env.keys.encrypted" ]; then
    echo "🔐 Encrypting dotenvx key with vhsm..."
    echo "   (You'll be prompted for a passphrase)"
    cd ..
    vhsm encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
    cd test-app
    
    # Set secure permissions
    chmod 600 .env.keys.encrypted
    echo "✅ Key encrypted and secured"
else
    echo "✅ Encrypted key already exists"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "To test vhsm, run from project root:"
echo "  vhsm run -k test-app/.env.keys.encrypted -- node test-app/server.js"
echo ""

