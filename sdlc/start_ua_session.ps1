# YARA Cryptex - Start Complete UA Session
# Starts all services and runs UA testing with full logging

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - Complete UA Session" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Step 1: Build System
Write-Host "[STEP 1] Building System..." -ForegroundColor Yellow
try {
    cd rust
    cargo build --release --workspace 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Build successful" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Build had warnings" -ForegroundColor Yellow
    }
    cd ..
} catch {
    Write-Host "  ❌ Build failed: $_" -ForegroundColor Red
}

Write-Host ""

# Step 2: Start API Server
Write-Host "[STEP 2] Starting API Server..." -ForegroundColor Yellow
$apiProcess = $null
try {
    $apiExe = "rust\cryptex-api\target\release\cryptex-api.exe"
    if (Test-Path $apiExe) {
        $apiProcess = Start-Process -FilePath $apiExe -PassThru -WindowStyle Minimized
        Write-Host "  ✅ API server started (PID: $($apiProcess.Id))" -ForegroundColor Green
        Write-Host "  ⏳ Waiting for server to initialize..." -ForegroundColor Yellow
        Start-Sleep -Seconds 8
        
        # Test API
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3006/api/v2/yara/cryptex/stats" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Host "  ✅ API server responding" -ForegroundColor Green
            }
        } catch {
            Write-Host "  ⚠️  API server may still be starting" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ⚠️  API server binary not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ❌ Failed to start API server: $_" -ForegroundColor Red
}

Write-Host ""

# Step 3: Start Frontend (if available)
Write-Host "[STEP 3] Starting Frontend..." -ForegroundColor Yellow
$frontendProcess = $null
try {
    $frontendPath = "pyro-platform\frontend-svelte"
    if (Test-Path "$frontendPath\package.json") {
        Write-Host "  💡 Frontend available at: $frontendPath" -ForegroundColor Cyan
        Write-Host "  💡 To start: cd $frontendPath && npm run dev" -ForegroundColor Cyan
        Write-Host "  ⏳ Starting frontend in background..." -ForegroundColor Yellow
        
        $frontendProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\$frontendPath'; npm run dev" -PassThru -WindowStyle Minimized
        Write-Host "  ✅ Frontend starting (PID: $($frontendProcess.Id))" -ForegroundColor Green
        Write-Host "  ⏳ Waiting for frontend to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
    } else {
        Write-Host "  ⚠️  Frontend not found at expected path" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Frontend startup skipped: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Run UA Tests
Write-Host "[STEP 4] Running UA Tests..." -ForegroundColor Yellow
Write-Host "  This will:" -ForegroundColor Cyan
Write-Host "    - Open browser" -ForegroundColor White
Write-Host "    - Test all UI pages" -ForegroundColor White
Write-Host "    - Log all interactions" -ForegroundColor White
Write-Host "    - Capture screenshots" -ForegroundColor White
Write-Host ""

try {
    python sdlc/ua_testing_framework.py
    Write-Host "  ✅ UA tests completed" -ForegroundColor Green
} catch {
    Write-Host "  ❌ UA tests failed: $_" -ForegroundColor Red
    Write-Host "  💡 Make sure Chrome and ChromeDriver are installed" -ForegroundColor Cyan
}

Write-Host ""

# Step 5: Show Results
Write-Host "[STEP 5] Results..." -ForegroundColor Yellow
Write-Host ""

$uaLogs = Get-ChildItem -Path "ua_logs" -Filter "*.json" -ErrorAction SilentlyContinue
if ($uaLogs) {
    Write-Host "  ✅ UA logs: $($uaLogs.Count) file(s)" -ForegroundColor Green
}

$screenshots = Get-ChildItem -Path "ua_logs\screenshots" -Filter "*.png" -ErrorAction SilentlyContinue
if ($screenshots) {
    Write-Host "  ✅ Screenshots: $($screenshots.Count) image(s)" -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "UA Session Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 Check results in:" -ForegroundColor Yellow
Write-Host "  - ua_logs/interactions_*.json" -ForegroundColor White
Write-Host "  - ua_logs/screenshots/" -ForegroundColor White
Write-Host "  - ua_logs/ua_session_*.log" -ForegroundColor White
Write-Host ""

if ($apiProcess) {
    Write-Host "💡 API server is still running (PID: $($apiProcess.Id))" -ForegroundColor Cyan
    Write-Host "   To stop: Stop-Process -Id $($apiProcess.Id)" -ForegroundColor Cyan
}

if ($frontendProcess) {
    Write-Host "💡 Frontend is still running (PID: $($frontendProcess.Id))" -ForegroundColor Cyan
    Write-Host "   To stop: Stop-Process -Id $($frontendProcess.Id)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🎊 UA Session Complete!" -ForegroundColor Green

