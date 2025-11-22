# Generate Comprehensive YARA Rules Test Report
# Analyzes all test results and creates a detailed report

param(
    [string]$ResultsDir = "test_rules",
    [string]$OutputReport = "test_rules\YARA_RULES_TEST_REPORT.md"
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Rules Test Report Generator" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

$resultsPath = Join-Path $rootDir $ResultsDir
$resultFiles = Get-ChildItem -Path $resultsPath -Filter "result_*.json" -ErrorAction SilentlyContinue

if ($resultFiles.Count -eq 0) {
    Write-Host "⚠️  No result files found in: $resultsPath" -ForegroundColor Yellow
    Write-Host "   Run: .\tools\test_yara_rules.ps1 first" -ForegroundColor Yellow
    exit 1
}

Write-Host "📊 Analyzing $($resultFiles.Count) test results..." -ForegroundColor Cyan

$report = @"
# YARA Rules Test Report

**Generated**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Total Tests**: $($resultFiles.Count)

---

## Summary

"@

$successCount = 0
$warningCount = 0
$errorCount = 0
$totalMatches = 0
$totalScanned = 0
$ruleDetails = @()

foreach ($file in $resultFiles) {
    try {
        $data = Get-Content $file.FullName | ConvertFrom-Json
        
        $ruleName = $file.BaseName -replace "result_", ""
        $matches = if ($data.matches) { $data.matches.Count } else { 0 }
        $scanned = if ($data.total_scanned) { $data.total_scanned } else { 0 }
        
        $status = "✅ Success"
        if ($data.error) {
            $status = "❌ Error"
            $errorCount++
        } elseif ($matches -gt 0) {
            $status = "🔍 Matches Found"
            $successCount++
        } else {
            $successCount++
        }
        
        $totalMatches += $matches
        $totalScanned += $scanned
        
        $ruleDetails += [PSCustomObject]@{
            Rule = $ruleName
            Status = $status
            Matches = $matches
            Scanned = $scanned
            File = $file.Name
        }
    } catch {
        $warningCount++
        $ruleDetails += [PSCustomObject]@{
            Rule = $file.BaseName -replace "result_", ""
            Status = "⚠️ Parse Error"
            Matches = 0
            Scanned = 0
            File = $file.Name
        }
    }
}

$report += @"

- **✅ Successful**: $successCount
- **⚠️ Warnings**: $warningCount
- **❌ Errors**: $errorCount
- **🔍 Total Matches**: $totalMatches
- **📁 Total Files Scanned**: $totalScanned

---

## Test Results by Rule

| Rule | Status | Matches | Files Scanned |
|------|--------|---------|--------------|
"@

foreach ($detail in $ruleDetails | Sort-Object Rule) {
    $report += "| $($detail.Rule) | $($detail.Status) | $($detail.Matches) | $($detail.Scanned) |`n"
}

$report += @"

---

## Rules with Matches

"@

$rulesWithMatches = $ruleDetails | Where-Object { $_.Matches -gt 0 }
if ($rulesWithMatches.Count -gt 0) {
    foreach ($rule in $rulesWithMatches) {
        $report += "- **$($rule.Rule)**: $($rule.Matches) matches`n"
    }
} else {
    $report += "No matches found in test files (this is normal for clean system files).`n"
}

$report += @"

---

## Recommendations

"@

if ($successCount -gt 0) {
    $report += @"
- ✅ $successCount rules tested successfully
- Ready for production use
- Consider testing with more diverse file types
- Test with Cryptex transcoding for branded output
"@
}

if ($errorCount -gt 0) {
    $report += @"

### Issues Found
- $errorCount rules had errors (may need rule syntax fixes)
- Review error details in individual result files
"@
}

$report += @"

---

## Next Steps

1. **Test More Rules**: `.\tools\test_yara_rules.ps1 -MaxRules 100`
2. **Test Real Files**: `.\tools\test_yara_rules.ps1 -TestTarget "C:\Path\To\Scan"`
3. **Use Cryptex**: `.\tools\test_yara_rules.ps1 -UseCryptex`
4. **View Results**: `Get-Content test_rules\result_*.json`

---

## Files

- **Results Directory**: `$ResultsDir`
- **Total Result Files**: $($resultFiles.Count)
- **Report Generated**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

# Save report
$outputPath = Join-Path $rootDir $OutputReport
$report | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "✅ Report generated: $outputPath" -ForegroundColor Green
Write-Host "`n📊 Report Summary:" -ForegroundColor Cyan
Write-Host "   ✅ Successful: $successCount" -ForegroundColor Green
Write-Host "   ⚠️  Warnings: $warningCount" -ForegroundColor Yellow
Write-Host "   ❌ Errors: $errorCount" -ForegroundColor Red
Write-Host "   🔍 Total Matches: $totalMatches" -ForegroundColor Cyan
Write-Host "   📁 Total Scanned: $totalScanned" -ForegroundColor Cyan

