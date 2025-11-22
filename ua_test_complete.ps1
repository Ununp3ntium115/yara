# Complete UA Test Script for YARA Cryptex
# Tests: Feed Scanner, YARA Scanning, API Server, and UI Components

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex Complete UA Test Suite" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$testResults = @{
    FeedScanner = $false
    YaraScanner = $false
    ApiServer = $false
    UIComponents = $false
    CryptexDict = $false
}

# Test 1: Use Existing YARA Rules
Write-Host "[TEST 1] Testing with existing YARA rules..." -ForegroundColor Yellow
$testFile = "sample.file"
$testRules = "yara-rules\index.yar"

if (Test-Path $testRules) {
    Write-Host "  ✅ Found rules file: $testRules" -ForegroundColor Green
    
    if (Test-Path $testFile) {
        try {
            python yara_scanner.py --rules $testRules --target $testFile --output ua_scan_results.json 2>&1 | Out-Null
            if (Test-Path "ua_scan_results.json") {
                $results = Get-Content "ua_scan_results.json" | ConvertFrom-Json
                Write-Host "  ✅ YARA scan completed successfully" -ForegroundColor Green
                Write-Host "     Scanned: $($results.total_scanned) files" -ForegroundColor Cyan
                Write-Host "     Matches: $($results.total_matches) matches" -ForegroundColor Cyan
                $testResults.YaraScanner = $true
            }
        } catch {
            Write-Host "  ❌ YARA scan failed: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⚠️  Test file not found, creating one..." -ForegroundColor Yellow
        "Test content for YARA scanning" | Out-File -FilePath $testFile -Encoding utf8
        python yara_scanner.py --rules $testRules --target $testFile --output ua_scan_results.json 2>&1 | Out-Null
        if (Test-Path "ua_scan_results.json") {
            $testResults.YaraScanner = $true
            Write-Host "  ✅ YARA scan completed" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  ⚠️  Rules file not found at $testRules" -ForegroundColor Yellow
}

Write-Host ""

# Test 2: API Server
Write-Host "[TEST 2] Testing API Server..." -ForegroundColor Yellow
$apiProcess = $null
try {
    $apiExe = "rust\cryptex-api\target\release\cryptex-api.exe"
    if (Test-Path $apiExe) {
        Write-Host "  ✅ API server executable found" -ForegroundColor Green
        $apiProcess = Start-Process -FilePath $apiExe -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 5
        
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3006/api/v2/yara/cryptex/stats" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Host "  ✅ API server responding!" -ForegroundColor Green
                $stats = $response.Content | ConvertFrom-Json
                Write-Host "     Status: $($stats.success)" -ForegroundColor Cyan
                if ($stats.data) {
                    Write-Host "     Total entries: $($stats.data.total_entries)" -ForegroundColor Cyan
                }
                $testResults.ApiServer = $true
            }
        } catch {
            Write-Host "  ⚠️  API server not ready: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ⚠️  API server executable not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ❌ API server test failed: $_" -ForegroundColor Red
}

Write-Host ""

# Test 3: UI Components
Write-Host "[TEST 3] Verifying UI Components..." -ForegroundColor Yellow
$uiComponents = @(
    @{Path="pyro-platform\frontend-svelte\src\routes\tools\yara\cryptex\+page.svelte"; Name="Cryptex Browser"},
    @{Path="pyro-platform\frontend-svelte\src\routes\tools\yara\feed\+page.svelte"; Name="Feed Scanner"},
    @{Path="pyro-platform\frontend-svelte\src\routes\tools\yara\scan\+page.svelte"; Name="YARA Scanner"}
)

$uiCount = 0
foreach ($component in $uiComponents) {
    if (Test-Path $component.Path) {
        Write-Host "  ✅ $($component.Name)" -ForegroundColor Green
        $uiCount++
    } else {
        Write-Host "  ❌ $($component.Name) - NOT FOUND" -ForegroundColor Red
    }
}

if ($uiCount -eq $uiComponents.Count) {
    $testResults.UIComponents = $true
    Write-Host "  ✅ All UI components present" -ForegroundColor Green
}

Write-Host ""

# Test 4: Cryptex Dictionary
Write-Host "[TEST 4] Testing Cryptex Dictionary..." -ForegroundColor Yellow
if (Test-Path "data\cryptex.json") {
    $dict = Get-Content "data\cryptex.json" | ConvertFrom-Json
    $entryCount = if ($dict.entries) { $dict.entries.Count } else { 0 }
    Write-Host "  ✅ Dictionary file found" -ForegroundColor Green
    Write-Host "     Entries: $entryCount" -ForegroundColor Cyan
    
    # Test CLI lookup
    try {
        $cliExe = "rust\cryptex-cli\target\release\cryptex.exe"
        if (Test-Path $cliExe) {
            $lookupResult = & $cliExe dict lookup yr_initialize 2>&1
            if ($LASTEXITCODE -eq 0 -or $lookupResult -match "yr_initialize") {
                Write-Host "  ✅ Dictionary lookup working" -ForegroundColor Green
                $testResults.CryptexDict = $true
            }
        }
    } catch {
        Write-Host "  ⚠️  CLI lookup test skipped" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠️  Dictionary file not found" -ForegroundColor Yellow
}

Write-Host ""

# Test 5: Feed Scanner (even if it returns 0 rules, test the functionality)
Write-Host "[TEST 5] Testing Feed Scanner..." -ForegroundColor Yellow
try {
    $feedExe = "rust\cryptex-cli\target\release\cryptex.exe"
    if (Test-Path $feedExe) {
        $feedResult = & $feedExe feed list 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ Feed scanner CLI working" -ForegroundColor Green
            $testResults.FeedScanner = $true
        }
    }
} catch {
    Write-Host "  ⚠️  Feed scanner test skipped" -ForegroundColor Yellow
}

Write-Host ""

# Final Summary
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "UA Test Results Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$passed = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$total = $testResults.Count

foreach ($test in $testResults.GetEnumerator() | Sort-Object Name) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$status - $($test.Key)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Overall: $passed/$total tests passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
Write-Host ""

# Cleanup
if ($apiProcess) {
    Write-Host "Cleaning up..." -ForegroundColor Yellow
    Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  ✅ API server stopped" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎊 UA Testing Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Test artifacts:" -ForegroundColor Cyan
Write-Host "  - ua_scan_results.json" -ForegroundColor White
Write-Host "  - test_malware_rules.json" -ForegroundColor White

