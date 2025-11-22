# YARA Cryptex - Windows 11 UA Test Runner
# Complete UA testing with full logging and iterative improvement

param(
    [int]$Cycles = 1,
    [switch]$Headless = $false,
    [switch]$KeepBrowserOpen = $false
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - Windows 11 UA Test Runner" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Check prerequisites
Write-Host "[CHECK] Prerequisites..." -ForegroundColor Yellow

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  ✅ Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Python not found" -ForegroundColor Red
    exit 1
}

# Check Chrome
try {
    $chromePath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction SilentlyContinue
    if ($chromePath) {
        Write-Host "  ✅ Chrome: Installed" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Chrome: Not found in registry (may still work)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Chrome: Could not verify" -ForegroundColor Yellow
}

# Check Rust
try {
    $rustVersion = rustc --version 2>&1
    Write-Host "  ✅ Rust: $rustVersion" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Rust: Not found (needed for building)" -ForegroundColor Yellow
}

# Check Node.js
try {
    $nodeVersion = node --version 2>&1
    Write-Host "  ✅ Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Node.js: Not found (needed for frontend)" -ForegroundColor Yellow
}

Write-Host ""

# Install Python dependencies
Write-Host "[SETUP] Installing Python dependencies..." -ForegroundColor Yellow
try {
    pip install -q -r sdlc/requirements.txt 2>&1 | Out-Null
    Write-Host "  ✅ Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Some dependencies may need manual installation" -ForegroundColor Yellow
    Write-Host "     Run: pip install selenium requests radon bandit" -ForegroundColor Cyan
}

Write-Host ""

# Create log directories
Write-Host "[SETUP] Creating log directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "sdlc\cycles" | Out-Null
New-Item -ItemType Directory -Force -Path "ua_logs\screenshots" | Out-Null
New-Item -ItemType Directory -Force -Path "sdlc\reports" | Out-Null
Write-Host "  ✅ Directories created" -ForegroundColor Green

Write-Host ""

# Run SDLC cycles
Write-Host "[TEST] Running $Cycles SDLC cycle(s)..." -ForegroundColor Yellow
Write-Host ""

for ($i = 1; $i -le $Cycles; $i++) {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Cycle $i of $Cycles" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Run complete SDLC cycle
        python sdlc/iterative_sdlc.py
        
        Write-Host ""
        Write-Host "  ✅ Cycle $i complete" -ForegroundColor Green
        Write-Host ""
        
        if ($i -lt $Cycles) {
            Write-Host "  Waiting 10 seconds before next cycle..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    } catch {
        Write-Host "  ❌ Cycle $i failed: $_" -ForegroundColor Red
        Write-Host "  Check logs for details" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "UA Testing Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Show results
Write-Host "📊 Results:" -ForegroundColor Yellow
Write-Host ""

# Security audit reports
$auditReports = Get-ChildItem -Path "sdlc" -Filter "security_audit_*.json" -ErrorAction SilentlyContinue
if ($auditReports) {
    Write-Host "  Security Audits: $($auditReports.Count) report(s)" -ForegroundColor White
    $auditReports | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
}

# Code simplification reports
$simplificationReports = Get-ChildItem -Path "sdlc" -Filter "code_simplification_*.json" -ErrorAction SilentlyContinue
if ($simplificationReports) {
    Write-Host "  Code Simplification: $($simplificationReports.Count) report(s)" -ForegroundColor White
    $simplificationReports | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
}

# Cycle reports
$cycleReports = Get-ChildItem -Path "sdlc\cycles" -Filter "cycle_*.json" -ErrorAction SilentlyContinue
if ($cycleReports) {
    Write-Host "  SDLC Cycles: $($cycleReports.Count) report(s)" -ForegroundColor White
    $cycleReports | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
}

# UA interaction logs
$uaLogs = Get-ChildItem -Path "ua_logs" -Filter "interactions_*.json" -ErrorAction SilentlyContinue
if ($uaLogs) {
    Write-Host "  UA Interactions: $($uaLogs.Count) log(s)" -ForegroundColor White
    $uaLogs | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
}

# Screenshots
$screenshots = Get-ChildItem -Path "ua_logs\screenshots" -Filter "*.png" -ErrorAction SilentlyContinue
if ($screenshots) {
    Write-Host "  Screenshots: $($screenshots.Count) image(s)" -ForegroundColor White
}

Write-Host ""
Write-Host "📁 All logs and reports saved in:" -ForegroundColor Yellow
Write-Host "  - sdlc/" -ForegroundColor White
Write-Host "  - ua_logs/" -ForegroundColor White
Write-Host ""

if (-not $KeepBrowserOpen) {
    Write-Host "💡 Tip: Review reports and screenshots to see what was tested" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🎊 SDLC Testing Complete!" -ForegroundColor Green

