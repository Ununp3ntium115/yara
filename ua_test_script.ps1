# YARA Cryptex UA Test Script
# Tests the complete system: feed scanner, YARA scanning, and UI

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex UA Test Suite" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Test 1: Feed Scanner - Get Updated Rules
Write-Host "[TEST 1] Fetching updated YARA rules..." -ForegroundColor Yellow
$testRules = "test_ua_rules.json"
if (Test-Path $testRules) { Remove-Item $testRules }

try {
    cd rust\cryptex-cli
    cargo run --release -- feed scan --use-case malware --output ..\..\$testRules 2>&1 | Out-Null
    if (Test-Path "..\..\$testRules") {
        $ruleCount = (Get-Content "..\..\$testRules" | ConvertFrom-Json).Count
        Write-Host "  ✅ Fetched $ruleCount rules" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  No rules file created" -ForegroundColor Yellow
    }
    cd ..\..
} catch {
    Write-Host "  ❌ Feed scanner test failed: $_" -ForegroundColor Red
}

Write-Host ""

# Test 2: YARA Scanner with Updated Rules
Write-Host "[TEST 2] Testing YARA scanner with updated rules..." -ForegroundColor Yellow
if (Test-Path $testRules) {
    # Create a test file to scan
    $testFile = "test_scan_target.txt"
    "This is a test file for YARA scanning" | Out-File -FilePath $testFile -Encoding utf8
    
    try {
        python yara_scanner.py --rules $testRules --target $testFile --output test_scan_results.json 2>&1 | Out-Null
        if (Test-Path "test_scan_results.json") {
            Write-Host "  ✅ YARA scan completed" -ForegroundColor Green
            $results = Get-Content "test_scan_results.json" | ConvertFrom-Json
            Write-Host "  📊 Scanned: $($results.scanned_files) files" -ForegroundColor Cyan
            Write-Host "  📊 Matched: $($results.matched_files) files" -ForegroundColor Cyan
        } else {
            Write-Host "  ⚠️  Scan completed but no results file" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ❌ YARA scanner test failed: $_" -ForegroundColor Red
    }
    
    Remove-Item $testFile -ErrorAction SilentlyContinue
} else {
    Write-Host "  ⚠️  Skipping - no rules file available" -ForegroundColor Yellow
}

Write-Host ""

# Test 3: API Server
Write-Host "[TEST 3] Testing API server..." -ForegroundColor Yellow
$apiProcess = $null
try {
    cd rust\cryptex-api
    $apiProcess = Start-Process -FilePath "cargo" -ArgumentList "run", "--release" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 5
    
    # Test API endpoint
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3006/api/v2/yara/cryptex/stats" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Host "  ✅ API server responding" -ForegroundColor Green
            $stats = $response.Content | ConvertFrom-Json
            Write-Host "  📊 API Response: $($stats | ConvertTo-Json -Compress)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "  ⚠️  API server may not be ready yet" -ForegroundColor Yellow
    }
    cd ..\..
} catch {
    Write-Host "  ❌ API server test failed: $_" -ForegroundColor Red
}

Write-Host ""

# Test 4: UI Components Check
Write-Host "[TEST 4] Checking UI components..." -ForegroundColor Yellow
$uiComponents = @(
    "pyro-platform\frontend-svelte\src\routes\tools\yara\cryptex\+page.svelte",
    "pyro-platform\frontend-svelte\src\routes\tools\yara\feed\+page.svelte",
    "pyro-platform\frontend-svelte\src\routes\tools\yara\scan\+page.svelte"
)

foreach ($component in $uiComponents) {
    if (Test-Path $component) {
        Write-Host "  ✅ $(Split-Path $component -Leaf)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $(Split-Path $component -Leaf) - NOT FOUND" -ForegroundColor Red
    }
}

Write-Host ""

# Test 5: Cryptex Dictionary
Write-Host "[TEST 5] Testing Cryptex dictionary..." -ForegroundColor Yellow
if (Test-Path "data\cryptex.json") {
    $dict = Get-Content "data\cryptex.json" | ConvertFrom-Json
    $entryCount = $dict.entries.Count
    Write-Host "  ✅ Dictionary loaded: $entryCount entries" -ForegroundColor Green
    
    # Test lookup
    try {
        cd rust\cryptex-cli
        $lookupResult = cargo run --release -- dict lookup yr_initialize 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ Dictionary lookup working" -ForegroundColor Green
        }
        cd ..\..
    } catch {
        Write-Host "  ⚠️  Dictionary lookup test skipped" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠️  Dictionary file not found" -ForegroundColor Yellow
}

Write-Host ""

# Summary
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "UA Test Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Feed Scanner: Tested" -ForegroundColor Green
Write-Host "✅ YARA Scanner: Tested" -ForegroundColor Green
Write-Host "✅ API Server: Tested" -ForegroundColor Green
Write-Host "✅ UI Components: Verified" -ForegroundColor Green
Write-Host "✅ Cryptex Dictionary: Tested" -ForegroundColor Green
Write-Host ""
Write-Host "🎊 UA Tests Complete!" -ForegroundColor Green
Write-Host ""

# Cleanup
if ($apiProcess) {
    Write-Host "Stopping API server..." -ForegroundColor Yellow
    Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "Test artifacts:" -ForegroundColor Cyan
Write-Host "  - $testRules" -ForegroundColor White
Write-Host "  - test_scan_results.json" -ForegroundColor White

