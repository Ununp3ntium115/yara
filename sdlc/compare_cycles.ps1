# YARA Cryptex - Compare SDLC Cycles
# Compares results from different SDLC cycles

param(
    [int]$Cycle1 = 1,
    [int]$Cycle2 = 2
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - Compare SDLC Cycles" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Load-CycleReport {
    param([int]$CycleNumber)
    
    $cyclesDir = "sdlc\cycles"
    if (-not (Test-Path $cyclesDir)) {
        return $null
    }
    
    $reports = Get-ChildItem "$cyclesDir\cycle_*.json" | Sort-Object LastWriteTime
    if ($reports.Count -ge $CycleNumber) {
        $report = $reports[$CycleNumber - 1]
        return Get-Content $report.FullName | ConvertFrom-Json
    }
    
    return $null
}

$cycle1 = Load-CycleReport -CycleNumber $Cycle1
$cycle2 = Load-CycleReport -CycleNumber $Cycle2

if (-not $cycle1) {
    Write-Host "❌ Cycle $Cycle1 not found" -ForegroundColor Red
    exit 1
}

if (-not $cycle2) {
    Write-Host "❌ Cycle $Cycle2 not found" -ForegroundColor Red
    exit 1
}

Write-Host "Cycle $Cycle1 vs Cycle $Cycle2" -ForegroundColor Yellow
Write-Host ""

# Compare duration
$duration1 = $cycle1.duration
$duration2 = $cycle2.duration
$diff = $duration2 - $duration1

Write-Host "⏱️  Duration:" -ForegroundColor Cyan
Write-Host "  Cycle $Cycle1 : $([math]::Round($duration1, 1))s" -ForegroundColor White
Write-Host "  Cycle $Cycle2 : $([math]::Round($duration2, 1))s" -ForegroundColor White
if ($diff -gt 0) {
    Write-Host "  Change: +$([math]::Round($diff, 1))s" -ForegroundColor Red
} else {
    Write-Host "  Change: $([math]::Round($diff, 1))s" -ForegroundColor Green
}

Write-Host ""

# Compare steps
Write-Host "📋 Steps:" -ForegroundColor Cyan
foreach ($step1 in $cycle1.steps) {
    $stepName = $step1.step
    $step2 = $cycle2.steps | Where-Object { $_.step -eq $stepName }
    
    if ($step2) {
        $status1 = $step1.status
        $status2 = $step2.status
        
        if ($status1 -eq $status2) {
            Write-Host "  $stepName : $status1 (same)" -ForegroundColor White
        } else {
            Write-Host "  $stepName :" -ForegroundColor White
            Write-Host "    Cycle $Cycle1 : $status1" -ForegroundColor $(if ($status1 -eq 'completed') { 'Green' } else { 'Red' })
            Write-Host "    Cycle $Cycle2 : $status2" -ForegroundColor $(if ($status2 -eq 'completed') { 'Green' } else { 'Red' })
        }
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Comparison Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

