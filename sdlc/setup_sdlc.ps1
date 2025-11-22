# YARA Cryptex - SDLC Framework Setup
# Installs all dependencies and verifies setup

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - SDLC Framework Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Step 1: Install Python Dependencies
Write-Host "[STEP 1] Installing Python Dependencies..." -ForegroundColor Yellow
try {
    pip install -q selenium requests radon bandit 2>&1 | Out-Null
    Write-Host "  ✅ Python dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Some dependencies may need manual installation" -ForegroundColor Yellow
    Write-Host "     Run: pip install selenium requests radon bandit" -ForegroundColor Cyan
}

Write-Host ""

# Step 2: Verify Installation
Write-Host "[STEP 2] Verifying Installation..." -ForegroundColor Yellow
try {
    python sdlc/verify_setup.py
} catch {
    Write-Host "  ⚠️  Verification had issues" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Create Directories
Write-Host "[STEP 3] Creating Directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "sdlc\cycles" | Out-Null
New-Item -ItemType Directory -Force -Path "ua_logs\screenshots" | Out-Null
New-Item -ItemType Directory -Force -Path "sdlc\reports" | Out-Null
Write-Host "  ✅ Directories created" -ForegroundColor Green

Write-Host ""

# Step 4: Check Optional Tools
Write-Host "[STEP 4] Checking Optional Tools..." -ForegroundColor Yellow

# Check cargo-audit
try {
    cargo audit --version 2>&1 | Out-Null
    Write-Host "  ✅ cargo-audit: Installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  cargo-audit: Not installed (optional)" -ForegroundColor Yellow
    Write-Host "     Install with: cargo install cargo-audit" -ForegroundColor Cyan
}

Write-Host ""

# Summary
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ SDLC Framework Ready" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
Write-Host "   1. Run first cycle: .\sdlc\run_first_cycle.ps1" -ForegroundColor White
Write-Host "   2. Or run complete session: .\sdlc\start_ua_session.ps1" -ForegroundColor White
Write-Host ""
Write-Host "📊 The framework will:" -ForegroundColor Yellow
Write-Host "   • Log all UI interactions" -ForegroundColor White
Write-Host "   • Capture screenshots" -ForegroundColor White
Write-Host "   • Audit security" -ForegroundColor White
Write-Host "   • Analyze code complexity" -ForegroundColor White
Write-Host ""
Write-Host "🎊 Ready to start SDLC cycles!" -ForegroundColor Green

