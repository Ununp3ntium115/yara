# YARA Scanner PowerShell Wrapper
# Usage: .\scan.ps1 -Directory "C:\Path\To\Scan" [-RulesType malware|webshells|all]

param(
    [Parameter(Mandatory=$true)]
    [string]$Directory,

    [Parameter(Mandatory=$false)]
    [ValidateSet('all', 'malware', 'webshells', 'cve', 'packers', 'maldocs', 'capabilities')]
    [string]$RulesType = 'all',

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "",

    [Parameter(Mandatory=$false)]
    [switch]$NoRecursive
)

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set the rules file based on type
$RulesFile = switch ($RulesType) {
    'all'          { Join-Path $ScriptDir "yara-rules\index.yar" }
    'malware'      { Join-Path $ScriptDir "yara-rules\malware_index.yar" }
    'webshells'    { Join-Path $ScriptDir "yara-rules\webshells_index.yar" }
    'cve'          { Join-Path $ScriptDir "yara-rules\cve_rules_index.yar" }
    'packers'      { Join-Path $ScriptDir "yara-rules\packers_index.yar" }
    'maldocs'      { Join-Path $ScriptDir "yara-rules\maldocs_index.yar" }
    'capabilities' { Join-Path $ScriptDir "yara-rules\capabilities_index.yar" }
}

# Build the Python command
$PythonScript = Join-Path $ScriptDir "yara_scanner.py"
$Args = @("-r", $RulesFile, "-d", $Directory)

if ($NoRecursive) {
    $Args += "--no-recursive"
}

if ($OutputFile -ne "") {
    $Args += @("-o", $OutputFile)
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "YARA System Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Directory: $Directory" -ForegroundColor Yellow
Write-Host "Rules Type: $RulesType" -ForegroundColor Yellow
Write-Host "Rules File: $RulesFile" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if directory exists
if (-not (Test-Path $Directory)) {
    Write-Host "[ERROR] Directory does not exist: $Directory" -ForegroundColor Red
    exit 1
}

# Check if rules file exists
if (-not (Test-Path $RulesFile)) {
    Write-Host "[ERROR] Rules file does not exist: $RulesFile" -ForegroundColor Red
    exit 1
}

# Run the Python scanner
& python $PythonScript @Args

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Scan Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
