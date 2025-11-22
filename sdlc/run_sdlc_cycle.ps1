# YARA Cryptex - SDLC Cycle Runner
# Runs complete SDLC cycle with security audit, code simplification, and UA testing

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - SDLC Cycle" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Check Python
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version
    Write-Host "  ✅ $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Python not found" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "`n[2/5] Installing dependencies..." -ForegroundColor Yellow
try {
    pip install -r sdlc/requirements.txt 2>&1 | Out-Null
    Write-Host "  ✅ Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Some dependencies may not be installed" -ForegroundColor Yellow
}

# Run Security Audit
Write-Host "`n[3/5] Running Security Audit..." -ForegroundColor Yellow
try {
    python sdlc/security_audit.py
    Write-Host "  ✅ Security audit complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Security audit had issues" -ForegroundColor Yellow
}

# Run Code Simplification
Write-Host "`n[4/5] Running Code Simplification Analysis..." -ForegroundColor Yellow
try {
    python sdlc/code_simplification.py
    Write-Host "  ✅ Code simplification analysis complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Code simplification had issues" -ForegroundColor Yellow
}

# Run SDLC Cycle
Write-Host "`n[5/5] Running Complete SDLC Cycle..." -ForegroundColor Yellow
Write-Host "  This will:" -ForegroundColor Cyan
Write-Host "    - Run security audit" -ForegroundColor White
Write-Host "    - Run code simplification" -ForegroundColor White
Write-Host "    - Build system" -ForegroundColor White
Write-Host "    - Start services" -ForegroundColor White
Write-Host "    - Run UA tests" -ForegroundColor White
Write-Host ""

try {
    python sdlc/iterative_sdlc.py
    Write-Host "  ✅ SDLC cycle complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  SDLC cycle had issues" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "SDLC Cycle Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 Reports generated in:" -ForegroundColor Yellow
Write-Host "  - sdlc/security_audit_*.json" -ForegroundColor White
Write-Host "  - sdlc/code_simplification_*.json" -ForegroundColor White
Write-Host "  - sdlc/cycles/cycle_*.json" -ForegroundColor White
Write-Host "  - ua_logs/*.json" -ForegroundColor White
Write-Host ""
Write-Host "📸 Screenshots in:" -ForegroundColor Yellow
Write-Host "  - ua_logs/screenshots/" -ForegroundColor White
Write-Host ""

