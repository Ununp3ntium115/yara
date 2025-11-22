# Test all YARA Cryptex API endpoints

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Testing YARA Cryptex API Endpoints" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:3006/api/v2/yara/cryptex"
$tests = @()

# Test 1: Stats
Write-Host "[TEST 1] GET /stats" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/stats" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        $data = $response.Content | ConvertFrom-Json
        Write-Host "  ✅ Success" -ForegroundColor Green
        Write-Host "     Response: $($data | ConvertTo-Json -Compress)" -ForegroundColor Cyan
        $tests += @{Test="Stats"; Status="PASS"}
    }
} catch {
    Write-Host "  ❌ Failed: $_" -ForegroundColor Red
    $tests += @{Test="Stats"; Status="FAIL"}
}

Write-Host ""

# Test 2: Entries
Write-Host "[TEST 2] GET /entries" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/entries" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        $data = $response.Content | ConvertFrom-Json
        $count = if ($data.data) { $data.data.Count } else { 0 }
        Write-Host "  ✅ Success" -ForegroundColor Green
        Write-Host "     Entries: $count" -ForegroundColor Cyan
        $tests += @{Test="Entries"; Status="PASS"}
    }
} catch {
    Write-Host "  ❌ Failed: $_" -ForegroundColor Red
    $tests += @{Test="Entries"; Status="FAIL"}
}

Write-Host ""

# Test 3: Search
Write-Host "[TEST 3] GET /search?query=initialize" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/search?query=initialize" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        $data = $response.Content | ConvertFrom-Json
        $count = if ($data.data) { $data.data.Count } else { 0 }
        Write-Host "  ✅ Success" -ForegroundColor Green
        Write-Host "     Results: $count" -ForegroundColor Cyan
        $tests += @{Test="Search"; Status="PASS"}
    }
} catch {
    Write-Host "  ❌ Failed: $_" -ForegroundColor Red
    $tests += @{Test="Search"; Status="FAIL"}
}

Write-Host ""

# Test 4: Lookup
Write-Host "[TEST 4] GET /lookup?symbol=yr_initialize" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/lookup?symbol=yr_initialize" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        $data = $response.Content | ConvertFrom-Json
        Write-Host "  ✅ Success" -ForegroundColor Green
        if ($data.data) {
            Write-Host "     Found: $($data.data.symbol)" -ForegroundColor Cyan
        } else {
            Write-Host "     Entry not found (expected if DB not initialized)" -ForegroundColor Yellow
        }
        $tests += @{Test="Lookup"; Status="PASS"}
    }
} catch {
    Write-Host "  ❌ Failed: $_" -ForegroundColor Red
    $tests += @{Test="Lookup"; Status="FAIL"}
}

Write-Host ""

# Summary
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
$passed = ($tests | Where-Object { $_.Status -eq "PASS" }).Count
$total = $tests.Count
foreach ($test in $tests) {
    $color = if ($test.Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "$($test.Status) - $($test.Test)" -ForegroundColor $color
}
Write-Host ""
Write-Host "Overall: $passed/$total tests passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
Write-Host ""

