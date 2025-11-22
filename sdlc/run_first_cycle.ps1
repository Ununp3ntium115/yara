# YARA Cryptex - Run First SDLC Cycle
# Simplified script for first-time users

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - First SDLC Cycle" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Step 1: Verify Setup
Write-Host "[STEP 1] Verifying Setup..." -ForegroundColor Yellow
try {
    python sdlc/verify_setup.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n⚠️  Setup verification found issues" -ForegroundColor Yellow
        Write-Host "   Continuing anyway..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Verification skipped: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 2: Install Dependencies
Write-Host "[STEP 2] Installing Dependencies..." -ForegroundColor Yellow
try {
    pip install -q -r sdlc/requirements.txt 2>&1 | Out-Null
    Write-Host "  ✅ Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Some dependencies may need manual installation" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Run Security Audit
Write-Host "[STEP 3] Running Security Audit..." -ForegroundColor Yellow
try {
    python sdlc/security_audit.py
    Write-Host "  ✅ Security audit complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Security audit had issues: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Run Code Simplification
Write-Host "[STEP 4] Running Code Simplification Analysis..." -ForegroundColor Yellow
try {
    python sdlc/code_simplification.py
    Write-Host "  ✅ Code simplification analysis complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Code simplification had issues: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 5: Build System
Write-Host "[STEP 5] Building System..." -ForegroundColor Yellow
try {
    cd rust
    cargo build --release --workspace 2>&1 | Select-String -Pattern "Finished|error" | Select-Object -Last 3
    cd ..
    Write-Host "  ✅ Build complete" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  Build had issues: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 6: Start Services and Run UA Tests
Write-Host "[STEP 6] Starting Services and Running UA Tests..." -ForegroundColor Yellow
Write-Host "  This will:" -ForegroundColor Cyan
Write-Host "    - Start API server" -ForegroundColor White
Write-Host "    - Open browser" -ForegroundColor White
Write-Host "    - Test UI pages" -ForegroundColor White
Write-Host "    - Log all interactions" -ForegroundColor White
Write-Host "    - Capture screenshots" -ForegroundColor White
Write-Host ""

try {
    # Start API server in background
    $apiExe = "rust\cryptex-api\target\release\cryptex-api.exe"
    if (Test-Path $apiExe) {
        $apiProcess = Start-Process -FilePath $apiExe -PassThru -WindowStyle Minimized
        Write-Host "  ✅ API server started (PID: $($apiProcess.Id))" -ForegroundColor Green
        Start-Sleep -Seconds 8
    }
    
    # Run UA tests
    python sdlc/ua_testing_framework.py
    
    Write-Host "  ✅ UA tests complete" -ForegroundColor Green
    
    # Stop API server
    if ($apiProcess) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "  ⚠️  UA testing had issues: $_" -ForegroundColor Yellow
    Write-Host "  💡 Make sure Chrome is installed" -ForegroundColor Cyan
}

Write-Host ""

# Step 7: Show Results
Write-Host "[STEP 7] Results..." -ForegroundColor Yellow
Write-Host ""

$auditReports = Get-ChildItem -Path "sdlc" -Filter "security_audit_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($auditReports) {
    Write-Host "  📊 Security Audit: $($auditReports.Name)" -ForegroundColor Cyan
}

$simplificationReports = Get-ChildItem -Path "sdlc" -Filter "code_simplification_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($simplificationReports) {
    Write-Host "  📊 Code Simplification: $($simplificationReports.Name)" -ForegroundColor Cyan
}

$uaLogs = Get-ChildItem -Path "ua_logs" -Filter "interactions_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($uaLogs) {
    Write-Host "  📊 UA Interactions: $($uaLogs.Name)" -ForegroundColor Cyan
}

$screenshots = Get-ChildItem -Path "ua_logs\screenshots" -Filter "*.png" -ErrorAction SilentlyContinue
if ($screenshots) {
    Write-Host "  📸 Screenshots: $($screenshots.Count) images" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "First SDLC Cycle Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📁 Check results in:" -ForegroundColor Yellow
Write-Host "  - sdlc/ (reports)" -ForegroundColor White
Write-Host "  - ua_logs/ (interactions and screenshots)" -ForegroundColor White
Write-Host ""
Write-Host "🔄 To run another cycle:" -ForegroundColor Yellow
Write-Host "  .\sdlc\start_ua_session.ps1" -ForegroundColor White
Write-Host ""
Write-Host "🎊 First cycle complete!" -ForegroundColor Green

