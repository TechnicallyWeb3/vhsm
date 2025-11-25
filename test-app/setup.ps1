# Setup script for vhsm test app (PowerShell)
# Run this from the project root

$ErrorActionPreference = "Stop"

Write-Host "🔧 Setting up vhsm test application..." -ForegroundColor Cyan
Write-Host ""

# Check if dotenvx is installed
try {
    $null = Get-Command dotenvx -ErrorAction Stop
    Write-Host "✅ dotenvx found" -ForegroundColor Green
} catch {
    Write-Host "❌ dotenvx not found. Installing..." -ForegroundColor Yellow
    npm install -g @dotenvx/dotenvx
}

# Check if vhsm is built
if (-not (Test-Path "dist/cli.js")) {
    Write-Host "❌ vhsm not built. Building..." -ForegroundColor Yellow
    npm run build
}

Set-Location test-app

# Install test app dependencies
Write-Host "📦 Installing test app dependencies..." -ForegroundColor Cyan
npm install

# Generate dotenvx key if it doesn't exist
if (-not (Test-Path ".env.keys")) {
    Write-Host "🔑 Generating dotenvx private key..." -ForegroundColor Cyan
    dotenvx encrypt
} else {
    Write-Host "✅ dotenvx key already exists" -ForegroundColor Green
}

# Encrypt the key if encrypted version doesn't exist
if (-not (Test-Path ".env.keys.encrypted")) {
    Write-Host "🔐 Encrypting dotenvx key with vhsm..." -ForegroundColor Cyan
    Write-Host "   (You'll be prompted for a passphrase)" -ForegroundColor Yellow
    Set-Location ..
    node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
    Set-Location test-app
    
    # Set secure permissions (Windows)
    $acl = Get-Acl .env.keys.encrypted
    $acl.SetAccessRuleProtection($true, $false)
    $permission = $env:USERNAME, "FullControl", "Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl .env.keys.encrypted $acl
    
    Write-Host "✅ Key encrypted and secured" -ForegroundColor Green
} else {
    Write-Host "✅ Encrypted key already exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To test vhsm, run from project root:" -ForegroundColor Cyan
Write-Host "  node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js"
Write-Host ""

