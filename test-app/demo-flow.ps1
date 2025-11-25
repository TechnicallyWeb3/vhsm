# Complete demonstration of vhsm workflow (PowerShell)
# Run this from the project root

$ErrorActionPreference = "Stop"

Write-Host "🎬 vhsm Complete Workflow Demonstration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location test-app

# Step 1: Setup
Write-Host "📦 Step 1: Installing dependencies..." -ForegroundColor Yellow
npm install | Out-Null
Write-Host "✅ Dependencies installed" -ForegroundColor Green
Write-Host ""

# Step 2: Create .env
Write-Host "📝 Step 2: Creating .env file..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    node create-env.js
} else {
    Write-Host "✅ .env file already exists" -ForegroundColor Green
}
Write-Host ""

# Step 3: Generate dotenvx key
Write-Host "🔑 Step 3: Generating dotenvx key..." -ForegroundColor Yellow
if (-not (Test-Path ".env.keys")) {
    try {
        $null = Get-Command dotenvx -ErrorAction Stop
        dotenvx encrypt | Out-Null
        Write-Host "✅ dotenvx key generated" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  dotenvx not found. Please install: npm install -g @dotenvx/dotenvx" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✅ dotenvx key already exists" -ForegroundColor Green
}
Write-Host ""

# Step 4: Encrypt key
Write-Host "🔐 Step 4: Encrypting key with vhsm..." -ForegroundColor Yellow
Set-Location ..
if (-not (Test-Path "test-app/.env.keys.encrypted")) {
    Write-Host "   (You'll be prompted for a passphrase)" -ForegroundColor Yellow
    node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted
    
    # Set secure permissions
    $acl = Get-Acl test-app/.env.keys.encrypted
    $acl.SetAccessRuleProtection($true, $false)
    $permission = $env:USERNAME, "FullControl", "Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl test-app/.env.keys.encrypted $acl
    
    Write-Host "✅ Key encrypted" -ForegroundColor Green
} else {
    Write-Host "✅ Encrypted key already exists" -ForegroundColor Green
}
Write-Host ""

# Step 5: Run with vhsm
Write-Host "🚀 Step 5: Running test server with vhsm..." -ForegroundColor Yellow
Write-Host "   (First run will prompt for passphrase)" -ForegroundColor Yellow
Write-Host ""
node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js

Write-Host ""
Write-Host "✅ Demonstration complete!" -ForegroundColor Green
Write-Host ""
Write-Host "💡 Try running again - it should use the cache (no prompt):" -ForegroundColor Cyan
Write-Host "   node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js"

