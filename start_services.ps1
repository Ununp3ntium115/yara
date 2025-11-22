# Start YARA Cryptex Services for UA Testing
# Starts API server and provides instructions for frontend

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Starting YARA Cryptex Services" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Start API Server
Write-Host "[1/2] Starting API Server..." -ForegroundColor Yellow
$apiProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\rust\cryptex-api'; Write-Host 'Cryptex API Server Starting...' -ForegroundColor Green; cargo run --release" -PassThru -WindowStyle Minimized

Write-Host "  ✅ API server process started (PID: $($apiProcess.Id))" -ForegroundColor Green
Write-Host "  ⏳ Waiting for server to start..." -ForegroundColor Yellow

Start-Sleep -Seconds 10

# Test API
Write-Host "`n[2/2] Testing API Server..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3006/api/v2/yara/cryptex/stats" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "  ✅ API Server is RUNNING!" -ForegroundColor Green
        Write-Host "  📍 URL: http://localhost:3006" -ForegroundColor Cyan
        $data = $response.Content | ConvertFrom-Json
        Write-Host "  📊 Status: $($data.success)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  ⚠️  API server may still be starting..." -ForegroundColor Yellow
    Write-Host "  💡 Wait a few more seconds and test manually" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. API Server: Running in separate window" -ForegroundColor Green
Write-Host "   Test: http://localhost:3006/api/v2/yara/cryptex/stats" -ForegroundColor White
Write-Host ""
Write-Host "2. Start Frontend:" -ForegroundColor Yellow
Write-Host "   cd pyro-platform\frontend-svelte" -ForegroundColor White
Write-Host "   npm run dev" -ForegroundColor White
Write-Host ""
Write-Host "3. Test UI in Browser:" -ForegroundColor Yellow
Write-Host "   - Cryptex: http://localhost:5173/tools/yara/cryptex" -ForegroundColor White
Write-Host "   - Feed: http://localhost:5173/tools/yara/feed" -ForegroundColor White
Write-Host "   - Scanner: http://localhost:5173/tools/yara/scan" -ForegroundColor White
Write-Host ""
Write-Host "4. To stop API server:" -ForegroundColor Yellow
Write-Host "   Close the PowerShell window or run:" -ForegroundColor White
Write-Host "   Stop-Process -Id $($apiProcess.Id)" -ForegroundColor White
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan

