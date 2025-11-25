#!/bin/bash

# Complete demonstration of vhsm workflow
# Run this from the project root

set -e

echo "🎬 vhsm Complete Workflow Demonstration"
echo "========================================"
echo ""

cd test-app

# Step 1: Setup
echo "📦 Step 1: Installing dependencies..."
npm install > /dev/null 2>&1
echo "✅ Dependencies installed"
echo ""

# Step 2: Create .env
echo "📝 Step 2: Creating .env file..."
if [ ! -f ".env" ]; then
    node create-env.js
else
    echo "✅ .env file already exists"
fi
echo ""

# Step 3: Generate dotenvx key
echo "🔑 Step 3: Generating dotenvx key..."
if [ ! -f ".env.keys" ]; then
    if command -v dotenvx &> /dev/null; then
        dotenvx encrypt > /dev/null 2>&1
        echo "✅ dotenvx key generated"
    else
        echo "⚠️  dotenvx not found. Please install: npm install -g @dotenvx/dotenvx"
        exit 1
    fi
else
    echo "✅ dotenvx key already exists"
fi
echo ""

# Step 4: Encrypt key
echo "🔐 Step 4: Encrypting key with vhsm..."
cd ..
if [ ! -f "test-app/.env.keys.encrypted" ]; then
    echo "   (You'll be prompted for a passphrase)"
    node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
    chmod 600 test-app/.env.keys.encrypted
    echo "✅ Key encrypted"
else
    echo "✅ Encrypted key already exists"
fi
echo ""

# Step 5: Run with vhsm
echo "🚀 Step 5: Running test server with vhsm..."
echo "   (First run will prompt for passphrase)"
echo ""
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js

echo ""
echo "✅ Demonstration complete!"
echo ""
echo "💡 Try running again - it should use the cache (no prompt):"
echo "   node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js"

