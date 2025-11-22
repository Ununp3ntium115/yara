# PowerShell build script for YARA Cryptex - Windows

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex Build System (Windows)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$BUILD_DIR = "build"
New-Item -ItemType Directory -Force -Path $BUILD_DIR | Out-Null

# Build Rust components
Write-Host "Building Rust components..." -ForegroundColor Blue
Set-Location rust

# Build cryptex-store
Write-Host "Building cryptex-store..." -ForegroundColor Yellow
Set-Location cryptex-store
cargo build --release
Set-Location ..

# Build cryptex-api
Write-Host "Building cryptex-api..." -ForegroundColor Yellow
Set-Location cryptex-api
cargo build --release
Set-Location ..

# Build yara-feed-scanner
Write-Host "Building yara-feed-scanner..." -ForegroundColor Yellow
Set-Location yara-feed-scanner
cargo build --release
Set-Location ..

# Build cryptex-cli
Write-Host "Building cryptex-cli..." -ForegroundColor Yellow
Set-Location cryptex-cli
cargo build --release
Set-Location ..

Set-Location ..

# Copy binaries
Write-Host "Copying binaries..." -ForegroundColor Blue
New-Item -ItemType Directory -Force -Path "$BUILD_DIR\bin" | Out-Null

Copy-Item "rust\cryptex-store\target\release\import_cryptex.exe" "$BUILD_DIR\bin\" -ErrorAction SilentlyContinue
Copy-Item "rust\cryptex-store\target\release\export_cryptex.exe" "$BUILD_DIR\bin\" -ErrorAction SilentlyContinue
Copy-Item "rust\cryptex-api\target\release\cryptex-api.exe" "$BUILD_DIR\bin\" -ErrorAction SilentlyContinue
Copy-Item "rust\yara-feed-scanner\target\release\yara-feed-scanner.exe" "$BUILD_DIR\bin\" -ErrorAction SilentlyContinue
Copy-Item "rust\cryptex-cli\target\release\cryptex.exe" "$BUILD_DIR\bin\" -ErrorAction SilentlyContinue

# Copy data files
Write-Host "Copying data files..." -ForegroundColor Blue
New-Item -ItemType Directory -Force -Path "$BUILD_DIR\data" | Out-Null
Copy-Item "data\cryptex.json" "$BUILD_DIR\data\" -ErrorAction SilentlyContinue

# Copy documentation
Write-Host "Copying documentation..." -ForegroundColor Blue
New-Item -ItemType Directory -Force -Path "$BUILD_DIR\docs" | Out-Null
Get-ChildItem -Filter "*.md" | Copy-Item -Destination "$BUILD_DIR\docs\" -ErrorAction SilentlyContinue

Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Binaries are in: $BUILD_DIR\bin\" -ForegroundColor Green

