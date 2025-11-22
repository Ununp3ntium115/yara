# YARA Cryptex - Show End Product
# Starts all services and opens the UI

param(
    [int]$ApiPort = 3006,
    [int]$FrontendPort = 5173,
    [switch]$BuildFirst = $false,
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Cryptex - Show End Product" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Function to check if port is in use
function Test-Port {
    param([int]$Port)
    $connection = Test-NetConnection -ComputerName localhost -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    return $connection
}

# Function to wait for service
function Wait-ForService {
    param(
        [string]$Url,
        [int]$MaxWait = 30
    )
    $waited = 0
    while ($waited -lt $MaxWait) {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                return $true
            }
        } catch {
            Start-Sleep -Seconds 1
            $waited++
        }
    }
    return $false
}

# Build if requested
if ($BuildFirst -and -not $SkipBuild) {
    Write-Host "🔨 Building Rust components..." -ForegroundColor Yellow
    Push-Location "$rootDir\rust"
    try {
        cargo build --release --workspace
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Build failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "✅ Build complete" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# Check if binaries exist
$apiBinary = "$rootDir\rust\cryptex-api\target\release\cryptex-api.exe"
$frontendDir = "$rootDir\pyro-platform\frontend-svelte"

if (-not (Test-Path $apiBinary)) {
    Write-Host "⚠️  API binary not found: $apiBinary" -ForegroundColor Yellow
    Write-Host "   Run with -BuildFirst to build it" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $frontendDir)) {
    Write-Host "⚠️  Frontend directory not found: $frontendDir" -ForegroundColor Yellow
    exit 1
}

# Check ports
if (Test-Port -Port $ApiPort) {
    Write-Host "⚠️  Port $ApiPort is already in use" -ForegroundColor Yellow
    $useExisting = Read-Host "Use existing service? (y/n)"
    if ($useExisting -ne "y") {
        exit 1
    }
} else {
    # Start API server
    Write-Host "🚀 Starting API server on port $ApiPort..." -ForegroundColor Yellow
    $apiProcess = Start-Process -FilePath $apiBinary -ArgumentList "--port", $ApiPort -PassThru -WindowStyle Minimized
    Start-Sleep -Seconds 2

    # Wait for API to be ready
    Write-Host "⏳ Waiting for API server..." -ForegroundColor Yellow
    $apiReady = Wait-ForService -Url "http://localhost:$ApiPort/api/v2/yara/cryptex/stats"
    if (-not $apiReady) {
        Write-Host "❌ API server failed to start!" -ForegroundColor Red
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Host "✅ API server ready" -ForegroundColor Green
}

# Check frontend
if (Test-Port -Port $FrontendPort) {
    Write-Host "⚠️  Port $FrontendPort is already in use" -ForegroundColor Yellow
    $useExisting = Read-Host "Use existing frontend? (y/n)"
    if ($useExisting -ne "y") {
        exit 1
    }
} else {
    # Start frontend
    Write-Host "🚀 Starting frontend on port $FrontendPort..." -ForegroundColor Yellow
    Push-Location $frontendDir
    try {
        $frontendProcess = Start-Process -FilePath "npm" -ArgumentList "run", "dev", "--", "--port", $FrontendPort -PassThru -WindowStyle Minimized
        Start-Sleep -Seconds 3

        # Wait for frontend to be ready
        Write-Host "⏳ Waiting for frontend..." -ForegroundColor Yellow
        $frontendReady = Wait-ForService -Url "http://localhost:$FrontendPort" -MaxWait 60
        if (-not $frontendReady) {
            Write-Host "⚠️  Frontend may still be starting..." -ForegroundColor Yellow
        } else {
            Write-Host "✅ Frontend ready" -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
}

# Open browser
Write-Host "`n🌐 Opening browser..." -ForegroundColor Yellow

$urls = @(
    "http://localhost:$FrontendPort/tools/yara/cryptex",
    "http://localhost:$FrontendPort/tools/yara/feed",
    "http://localhost:$FrontendPort/tools/yara/scan"
)

foreach ($url in $urls) {
    Start-Process $url
    Start-Sleep -Seconds 1
}

Write-Host "`n✅ End Product Ready!" -ForegroundColor Green
Write-Host "`n📊 Available Pages:" -ForegroundColor Cyan
Write-Host "   • Cryptex Dictionary: http://localhost:$FrontendPort/tools/yara/cryptex" -ForegroundColor White
Write-Host "   • Feed Scanner: http://localhost:$FrontendPort/tools/yara/feed" -ForegroundColor White
Write-Host "   • YARA Scanner: http://localhost:$FrontendPort/tools/yara/scan" -ForegroundColor White
Write-Host "`n🔌 API Endpoints:" -ForegroundColor Cyan
Write-Host "   • Stats: http://localhost:$ApiPort/api/v2/yara/cryptex/stats" -ForegroundColor White
Write-Host "   • Lookup: http://localhost:$ApiPort/api/v2/yara/cryptex/lookup?symbol=yr_initialize" -ForegroundColor White
Write-Host "   • Feed Scan: http://localhost:$ApiPort/api/v2/yara/feed/scan/all" -ForegroundColor White
Write-Host "`n💡 Press Ctrl+C to stop services" -ForegroundColor Yellow

# Keep script running
try {
    while ($true) {
        Start-Sleep -Seconds 10
        # Check if processes are still running
        if ($apiProcess -and -not (Get-Process -Id $apiProcess.Id -ErrorAction SilentlyContinue)) {
            Write-Host "⚠️  API server stopped" -ForegroundColor Yellow
            break
        }
    }
} catch {
    Write-Host "`n🛑 Stopping services..." -ForegroundColor Yellow
    if ($apiProcess) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($frontendProcess) {
        Stop-Process -Id $frontendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "✅ Services stopped" -ForegroundColor Green
}

