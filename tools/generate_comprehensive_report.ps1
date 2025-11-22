# Generate Comprehensive YARA Cryptex Report
# Combines scan results, test results, and system audit into a single report

param(
    [string]$ScanResults = "",
    [string]$TestResultsDir = "test_rules",
    [string]$AuditReport = "audit_report.json",
    [string]$OutputDir = "reports",
    [string[]]$Formats = @("html", "json")
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Cryptex - Comprehensive Report Generator" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Check for Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "❌ Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Build arguments
$scriptPath = Join-Path $rootDir "tools\report_generator.py"
$args = @()

if ($ScanResults) {
    $scanPath = Join-Path $rootDir $ScanResults
    if (Test-Path $scanPath) {
        $args += "--scan-results", $scanPath
    } else {
        Write-Host "⚠️  Scan results file not found: $scanPath" -ForegroundColor Yellow
    }
}

$testPath = Join-Path $rootDir $TestResultsDir
if (Test-Path $testPath) {
    $args += "--test-results", $testPath
} else {
    Write-Host "⚠️  Test results directory not found: $testPath" -ForegroundColor Yellow
}

$auditPath = Join-Path $rootDir $AuditReport
if (Test-Path $auditPath) {
    $args += "--audit-report", $auditPath
} else {
    Write-Host "⚠️  Audit report not found: $auditPath" -ForegroundColor Yellow
    Write-Host "   Run: python tools\self_audit.py first" -ForegroundColor Yellow
}

$outputPath = Join-Path $rootDir $OutputDir
$args += "--output-dir", $outputPath

$args += "--format"
$args += $Formats

# Run report generator
Write-Host "📊 Generating comprehensive report..." -ForegroundColor Cyan
Write-Host "   Formats: $($Formats -join ', ')" -ForegroundColor Gray

python $scriptPath $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Report generation complete!" -ForegroundColor Green
    Write-Host "`n📄 Generated Reports:" -ForegroundColor Cyan
    
    $reportFiles = Get-ChildItem -Path $outputPath -Filter "comprehensive_report_*" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
    foreach ($file in $reportFiles) {
        Write-Host "   • $($file.Name)" -ForegroundColor White
        if ($file.Extension -eq ".html") {
            Write-Host "     Open: $($file.FullName)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n💡 To view HTML report:" -ForegroundColor Yellow
    Write-Host "   Start-Process $outputPath\comprehensive_report_*.html" -ForegroundColor White
} else {
    Write-Host "`n❌ Report generation failed!" -ForegroundColor Red
    exit 1
}

