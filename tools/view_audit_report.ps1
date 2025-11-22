# View Audit Report
# Displays the audit report in a readable format

param(
    [string]$ReportFile = "audit_report.json"
)

$rootDir = $PSScriptRoot | Split-Path -Parent
$reportPath = Join-Path $rootDir $ReportFile

if (-not (Test-Path $reportPath)) {
    Write-Host "❌ Report file not found: $reportPath" -ForegroundColor Red
    Write-Host "   Run: python tools\self_audit.py" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Cryptex - Audit Report Viewer" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

$report = Get-Content $reportPath | ConvertFrom-Json

# Summary
Write-Host "📊 SUMMARY" -ForegroundColor Cyan
Write-Host "-" * 60
Write-Host "Status: $($report.summary.status)" -ForegroundColor $(if ($report.summary.total_issues -eq 0) { "Green" } else { "Yellow" })
Write-Host "Total Issues: $($report.summary.total_issues)" -ForegroundColor $(if ($report.summary.total_issues -eq 0) { "Green" } else { "Yellow" })
Write-Host "Total Success: $($report.summary.total_success)" -ForegroundColor Green
Write-Host "Has Gaps: $(if ($report.summary.has_gaps) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($report.summary.has_gaps) { "Yellow" } else { "Green" })
Write-Host ""

# Rust Components
Write-Host "🔧 RUST COMPONENTS" -ForegroundColor Cyan
Write-Host "-" * 60
foreach ($crateName in $report.rust.crates.PSObject.Properties.Name) {
    $crate = $report.rust.crates.$crateName
    $status = if ($crate.issues.Count -eq 0) { "✅" } else { "⚠️" }
    Write-Host "$status $crateName" -ForegroundColor $(if ($crate.issues.Count -eq 0) { "Green" } else { "Yellow" })
    if ($crate.issues.Count -gt 0) {
        foreach ($issue in $crate.issues) {
            Write-Host "   • $issue" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# redb Integration
Write-Host "💾 REDB INTEGRATION" -ForegroundColor Cyan
Write-Host "-" * 60
$redbIssues = $report.redb.issues.Count
$status = if ($redbIssues -eq 0) { "✅" } else { "⚠️" }
Write-Host "$status redb Integration" -ForegroundColor $(if ($redbIssues -eq 0) { "Green" } else { "Yellow" })
if ($redbIssues -gt 0) {
    foreach ($issue in $report.redb.issues) {
        Write-Host "   • $issue" -ForegroundColor Yellow
    }
}
Write-Host ""

# Node-RED Nodes
Write-Host "🔌 NODE-RED NODES" -ForegroundColor Cyan
Write-Host "-" * 60
foreach ($nodeName in $report.node_red.nodes.PSObject.Properties.Name) {
    $node = $report.node_red.nodes.$nodeName
    $status = if ($node.issues.Count -eq 0) { "✅" } else { "⚠️" }
    Write-Host "$status $nodeName" -ForegroundColor $(if ($node.issues.Count -eq 0) { "Green" } else { "Yellow" })
    if ($node.issues.Count -gt 0) {
        foreach ($issue in $node.issues) {
            Write-Host "   • $issue" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# Svelte Components
Write-Host "🎨 SVELTE COMPONENTS" -ForegroundColor Cyan
Write-Host "-" * 60
foreach ($compName in $report.svelte.components.PSObject.Properties.Name) {
    $comp = $report.svelte.components.$compName
    $status = if ($comp.issues.Count -eq 0) { "✅" } else { "⚠️" }
    Write-Host "$status $compName" -ForegroundColor $(if ($comp.issues.Count -eq 0) { "Green" } else { "Yellow" })
    if ($comp.issues.Count -gt 0) {
        foreach ($issue in $comp.issues) {
            Write-Host "   • $issue" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# API Endpoints
Write-Host "🌐 API ENDPOINTS" -ForegroundColor Cyan
Write-Host "-" * 60
$apiIssues = $report.api.issues.Count
$status = if ($apiIssues -eq 0) { "✅" } else { "⚠️" }
Write-Host "$status API Integration" -ForegroundColor $(if ($apiIssues -eq 0) { "Green" } else { "Yellow" })
if ($apiIssues -gt 0) {
    foreach ($issue in $report.api.issues) {
        Write-Host "   • $issue" -ForegroundColor Yellow
    }
}
Write-Host ""

# Gaps
if ($report.gaps.Count -gt 0) {
    Write-Host "⚠️ GAPS IDENTIFIED" -ForegroundColor Yellow
    Write-Host "-" * 60
    foreach ($gap in $report.gaps) {
        Write-Host "   • $gap" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Recommendations
Write-Host "💡 RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "-" * 60
if ($report.summary.total_issues -eq 0) {
    Write-Host "✅ All components complete!" -ForegroundColor Green
    Write-Host "   Ready to build and deploy" -ForegroundColor Green
} else {
    Write-Host "⚠️ Issues found - see details above" -ForegroundColor Yellow
    if ($report.rust.crates.PSObject.Properties.Name | ForEach-Object { $report.rust.crates.$_.issues } | Where-Object { $_ -like "*Binary*not built*" }) {
        Write-Host "   → Build binaries: cd rust && cargo build --release --workspace" -ForegroundColor White
    }
}
Write-Host ""

