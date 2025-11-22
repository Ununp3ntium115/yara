# Test YARA Rules on This PC
# Tests downloaded YARA rules against system files

param(
    [string]$RulesDir = "test_rules\yara-rules-extracted",
    [string]$TestTarget = $env:WINDIR,
    [string]$OutputFile = "test_rules\scan_results.json",
    [switch]$UseCryptex = $false,
    [int]$MaxRules = 10
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Rules Test on This PC" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

$rulesPath = Join-Path $rootDir $RulesDir
if (-not (Test-Path $rulesPath)) {
    Write-Host "❌ Rules directory not found: $rulesPath" -ForegroundColor Red
    Write-Host "   Run: .\tools\download_and_test_yara_rules.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Find YARA rule files
Write-Host "📂 Finding YARA rule files..." -ForegroundColor Yellow
$yarFiles = Get-ChildItem -Path $rulesPath -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
if ($yarFiles.Count -eq 0) {
    $yaraFiles = Get-ChildItem -Path $rulesPath -Filter "*.yara" -Recurse -ErrorAction SilentlyContinue
    if ($yaraFiles.Count -gt 0) {
        $yarFiles = $yaraFiles
    }
}

if ($yarFiles.Count -eq 0) {
    Write-Host "❌ No YARA rule files found in: $rulesPath" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Found $($yarFiles.Count) YARA rule files" -ForegroundColor Green

# Select a few rule files to test
$selectedRules = $yarFiles | Select-Object -First $MaxRules
Write-Host "`n🧪 Testing with $($selectedRules.Count) rule files:" -ForegroundColor Cyan
foreach ($rule in $selectedRules) {
    Write-Host "   • $($rule.Name)" -ForegroundColor White
}

# Create a test directory with some sample files
$testDir = Join-Path $env:TEMP "yara_test_scan"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
}

# Copy some system files for testing (safe files only)
Write-Host "`n📋 Preparing test files..." -ForegroundColor Yellow
$testFiles = @()
try {
    # Copy some safe system files
    $safeFiles = @(
        "$env:WINDIR\System32\notepad.exe",
        "$env:WINDIR\System32\calc.exe"
    )
    
    foreach ($file in $safeFiles) {
        if (Test-Path $file) {
            $destFile = Join-Path $testDir (Split-Path $file -Leaf)
            Copy-Item -Path $file -Destination $destFile -ErrorAction SilentlyContinue
            if (Test-Path $destFile) {
                $testFiles += $destFile
            }
        }
    }
    
    # Also create some text files
    "This is a test file" | Out-File -FilePath (Join-Path $testDir "test.txt") -Encoding UTF8
    $testFiles += (Join-Path $testDir "test.txt")
    
    Write-Host "✅ Prepared $($testFiles.Count) test files" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not prepare all test files: $_" -ForegroundColor Yellow
}

# Test each rule file individually
Write-Host "`n🔍 Testing rules..." -ForegroundColor Yellow
$results = @()
$scannerScript = Join-Path $rootDir "yara_scanner.py"

foreach ($ruleFile in $selectedRules) {
    Write-Host "`n   Testing: $($ruleFile.Name)" -ForegroundColor Cyan
    
    $cryptexFlag = if ($UseCryptex) { "--cryptex" } else { "" }
    $outputFile = Join-Path $rootDir "test_rules" "result_$($ruleFile.BaseName).json"
    
    try {
        $scannerArgs = @(
            "-r", $ruleFile.FullName,
            "-d", $testDir,
            "-o", $outputFile
        )
        if ($UseCryptex) {
            $scannerArgs += "--cryptex"
        }
        
        $result = python $scannerScript $scannerArgs 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Success" -ForegroundColor Green
            $results += @{
                Rule = $ruleFile.Name
                Status = "Success"
                Output = $outputFile
            }
        } else {
            Write-Host "   ⚠️  Issues (may be rule syntax)" -ForegroundColor Yellow
            $results += @{
                Rule = $ruleFile.Name
                Status = "Warning"
                Error = ($result | Select-Object -Last 1)
            }
        }
    } catch {
        Write-Host "   ❌ Error: $_" -ForegroundColor Red
        $results += @{
            Rule = $ruleFile.Name
            Status = "Error"
            Error = $_.ToString()
        }
    }
}

# Summary
Write-Host "`n📊 Test Summary:" -ForegroundColor Cyan
Write-Host "-" * 60
$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$warningCount = ($results | Where-Object { $_.Status -eq "Warning" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total rules tested: $($results.Count)" -ForegroundColor White
Write-Host "✅ Successful: $successCount" -ForegroundColor Green
Write-Host "⚠️  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "❌ Errors: $errorCount" -ForegroundColor Red

# Show results
if ($successCount -gt 0) {
    Write-Host "`n✅ Successful tests:" -ForegroundColor Green
    foreach ($result in $results | Where-Object { $_.Status -eq "Success" }) {
        Write-Host "   • $($result.Rule)" -ForegroundColor White
        if ($result.Output) {
            Write-Host "     Results: $($result.Output)" -ForegroundColor Gray
        }
    }
}

Write-Host "`n💡 Next steps:" -ForegroundColor Yellow
Write-Host "   • View results: Get-Content test_rules\result_*.json" -ForegroundColor White
Write-Host "   • Test with Cryptex: .\tools\test_yara_rules.ps1 -UseCryptex" -ForegroundColor White
Write-Host "   • Test more rules: .\tools\test_yara_rules.ps1 -MaxRules 50" -ForegroundColor White

