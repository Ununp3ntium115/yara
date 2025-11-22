# YARA Cryptex - Cleanup Old Logs
# Removes old logs and reports to free up space

param(
    [int]$DaysOld = 30,
    [switch]$DryRun = $false
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - Cleanup Old Logs" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$cutoffDate = (Get-Date).AddDays(-$DaysOld)
$deletedCount = 0
$totalSize = 0

function Cleanup-Directory {
    param(
        [string]$Path,
        [string]$Pattern
    )
    
    if (-not (Test-Path $Path)) {
        return
    }
    
    $files = Get-ChildItem -Path $Path -Filter $Pattern -Recurse -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        if ($file.LastWriteTime -lt $cutoffDate) {
            $size = $file.Length
            if ($DryRun) {
                Write-Host "  [DRY RUN] Would delete: $($file.FullName)" -ForegroundColor Yellow
                Write-Host "    Size: $([math]::Round($size / 1MB, 2)) MB | Age: $((Get-Date) - $file.LastWriteTime | Select-Object -ExpandProperty Days) days" -ForegroundColor Gray
            } else {
                try {
                    Remove-Item $file.FullName -Force
                    Write-Host "  ✅ Deleted: $($file.Name)" -ForegroundColor Green
                    $script:deletedCount++
                    $script:totalSize += $size
                } catch {
                    Write-Host "  ❌ Failed to delete: $($file.Name)" -ForegroundColor Red
                }
            }
        }
    }
}

Write-Host "Cleaning up files older than $DaysOld days..." -ForegroundColor Yellow
if ($DryRun) {
    Write-Host "  [DRY RUN MODE - No files will be deleted]" -ForegroundColor Cyan
}
Write-Host ""

# Cleanup logs
Write-Host "[1/4] Cleaning UA logs..." -ForegroundColor Yellow
Cleanup-Directory "ua_logs" "*.log"
Cleanup-Directory "ua_logs" "*.json"

# Cleanup screenshots
Write-Host "`n[2/4] Cleaning screenshots..." -ForegroundColor Yellow
Cleanup-Directory "ua_logs\screenshots" "*.png"

# Cleanup SDLC reports
Write-Host "`n[3/4] Cleaning SDLC reports..." -ForegroundColor Yellow
Cleanup-Directory "sdlc" "*.json"
Cleanup-Directory "sdlc\cycles" "*.json"

# Cleanup SDLC logs
Write-Host "`n[4/4] Cleaning SDLC logs..." -ForegroundColor Yellow
Cleanup-Directory "sdlc" "*.log"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "Dry Run Complete" -ForegroundColor Cyan
    Write-Host "  Run without -DryRun to actually delete files" -ForegroundColor Yellow
} else {
    Write-Host "Cleanup Complete" -ForegroundColor Cyan
    Write-Host "  Files deleted: $deletedCount" -ForegroundColor Green
    Write-Host "  Space freed: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Green
}
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

