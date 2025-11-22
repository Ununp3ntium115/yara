# YARA Cryptex - Export SDLC Results
# Exports all SDLC results to a single archive

param(
    [string]$OutputPath = "sdlc_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - Export SDLC Results" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Check if Compress-Archive is available
if (-not (Get-Command Compress-Archive -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Compress-Archive not available" -ForegroundColor Red
    Write-Host "   This requires PowerShell 5.0+" -ForegroundColor Yellow
    exit 1
}

# Create temp directory
$tempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
$exportDir = Join-Path $tempDir "sdlc_export"
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

Write-Host "Collecting files..." -ForegroundColor Yellow

# Copy SDLC reports
if (Test-Path "sdlc") {
    $sdlcExport = Join-Path $exportDir "sdlc"
    New-Item -ItemType Directory -Path $sdlcExport -Force | Out-Null
    
    Copy-Item "sdlc\*.json" $sdlcExport -ErrorAction SilentlyContinue
    Copy-Item "sdlc\*.log" $sdlcExport -ErrorAction SilentlyContinue
    Copy-Item "sdlc\cycles" $sdlcExport -Recurse -ErrorAction SilentlyContinue
    Write-Host "  ✅ SDLC reports" -ForegroundColor Green
}

# Copy UA logs
if (Test-Path "ua_logs") {
    $uaExport = Join-Path $exportDir "ua_logs"
    New-Item -ItemType Directory -Path $uaExport -Force | Out-Null
    
    Copy-Item "ua_logs\*.json" $uaExport -ErrorAction SilentlyContinue
    Copy-Item "ua_logs\*.log" $uaExport -ErrorAction SilentlyContinue
    
    # Copy screenshots (limit to recent ones)
    $screenshotsDir = Join-Path $uaExport "screenshots"
    New-Item -ItemType Directory -Path $screenshotsDir -Force | Out-Null
    Get-ChildItem "ua_logs\screenshots\*.png" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 50 | 
        Copy-Item -Destination $screenshotsDir -ErrorAction SilentlyContinue
    
    Write-Host "  ✅ UA logs and screenshots" -ForegroundColor Green
}

# Create summary
$summary = @"
YARA Cryptex - SDLC Results Export
====================================

Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Export Path: $OutputPath

Contents:
- SDLC reports and cycles
- UA interaction logs
- Screenshots (latest 50)
- Security audit reports
- Code simplification reports

To view results:
  .\sdlc\view_results.ps1

"@

$summary | Out-File (Join-Path $exportDir "README.txt") -Encoding UTF8

# Create archive
Write-Host "`nCreating archive..." -ForegroundColor Yellow
try {
    Compress-Archive -Path "$exportDir\*" -DestinationPath $OutputPath -Force
    Write-Host "  ✅ Archive created: $OutputPath" -ForegroundColor Green
    
    $size = (Get-Item $OutputPath).Length / 1MB
    Write-Host "  📦 Size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
} catch {
    Write-Host "  ❌ Failed to create archive: $_" -ForegroundColor Red
    exit 1
}

# Cleanup
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Export Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📦 Archive: $OutputPath" -ForegroundColor Green
Write-Host ""

