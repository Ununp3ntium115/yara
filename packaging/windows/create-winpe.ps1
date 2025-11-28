# R-YARA WinPE Creator
# Creates a bootable Windows PE image with R-YARA pre-installed
#
# Requirements:
#   - Windows ADK with WinPE add-on installed
#   - Administrator privileges
#
# Usage: .\create-winpe.ps1 [-OutputPath <path>] [-Architecture <amd64|x86>]

param(
    [string]$OutputPath = "C:\R-YARA-WinPE",
    [string]$Architecture = "amd64",
    [string]$RYaraBinPath = ".\dist"
)

# Require elevation
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Host "=============================================="
Write-Host "R-YARA WinPE Creator"
Write-Host "=============================================="
Write-Host "Architecture: $Architecture"
Write-Host "Output Path:  $OutputPath"
Write-Host ""

# Find Windows ADK
$ADKPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
$WinPEPath = "$ADKPath\Windows Preinstallation Environment"
$CopypePath = "$WinPEPath\$Architecture\copype.cmd"

if (-not (Test-Path $CopypePath)) {
    Write-Error "Windows ADK with WinPE add-on not found at: $WinPEPath"
    Write-Host "Please install Windows ADK and WinPE add-on from:"
    Write-Host "https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install"
    exit 1
}

# Create WinPE working directory
Write-Host "Step 1: Creating WinPE environment..."
if (Test-Path $OutputPath) {
    Remove-Item -Path $OutputPath -Recurse -Force
}

$env:Path += ";$ADKPath\Deployment Tools\$Architecture\Oscdimg"
& cmd /c "$CopypePath $Architecture $OutputPath"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create WinPE environment"
    exit 1
}

# Mount boot.wim
Write-Host ""
Write-Host "Step 2: Mounting boot.wim..."
$MountDir = "$OutputPath\mount"
$WimFile = "$OutputPath\media\sources\boot.wim"

New-Item -Path $MountDir -ItemType Directory -Force | Out-Null
& dism /Mount-Wim /WimFile:$WimFile /index:1 /MountDir:$MountDir

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to mount boot.wim"
    exit 1
}

try {
    # Copy R-YARA binaries
    Write-Host ""
    Write-Host "Step 3: Installing R-YARA..."

    $RYaraExe = Join-Path $RYaraBinPath "r-yara.exe"
    $RYaraServerExe = Join-Path $RYaraBinPath "r-yara-server.exe"

    if (-not (Test-Path $RYaraExe)) {
        Write-Warning "R-YARA binary not found at: $RYaraExe"
        Write-Host "Creating placeholder - replace with actual binaries"
        # Create placeholder
        "R-YARA placeholder - build actual binary with: cargo build --release --target x86_64-pc-windows-msvc" | Out-File "$MountDir\Windows\System32\r-yara.txt"
    } else {
        Copy-Item $RYaraExe "$MountDir\Windows\System32\" -Force
        Copy-Item $RYaraServerExe "$MountDir\Windows\System32\" -Force
    }

    # Create R-YARA directories
    New-Item -Path "$MountDir\R-YARA\rules" -ItemType Directory -Force | Out-Null
    New-Item -Path "$MountDir\R-YARA\data" -ItemType Directory -Force | Out-Null

    # Create configuration
    $Config = @"
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "scanner": {
    "rules_dir": "X:\\R-YARA\\rules",
    "data_dir": "X:\\R-YARA\\data"
  }
}
"@
    $Config | Out-File "$MountDir\R-YARA\config.json" -Encoding UTF8

    # Create sample rules
    $SampleRules = @"
rule IsPE : type {
    meta:
        description = "Detects PE files"
    strings:
        `$mz = "MZ" at 0
    condition:
        `$mz
}

rule IsELF : type {
    meta:
        description = "Detects ELF files"
    condition:
        uint32(0) == 0x464C457F
}
"@
    $SampleRules | Out-File "$MountDir\R-YARA\rules\default.yar" -Encoding UTF8

    # Create startup script
    Write-Host "Step 4: Configuring startup..."

    $StartScript = @"
@echo off
echo ========================================
echo  R-YARA Scanner - WinPE Edition
echo ========================================
echo.

REM Configure network
wpeinit

REM Wait for network
ping -n 3 127.0.0.1 > nul

REM Get IP address
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do set IP=%%a
set IP=%IP:~1%

echo Network IP: %IP%
echo.

REM Start R-YARA Server
echo Starting R-YARA Fire Hydrant API on port 8080...
start /b X:\Windows\System32\r-yara-server.exe server --port 8080

echo.
echo ========================================
echo R-YARA Scanner is ready!
echo ========================================
echo.
echo Web Interface: http://%IP%:8080
echo.
echo CLI Commands:
echo   r-yara scan C:\file.exe
echo   r-yara scan -r C:\folder
echo.

cmd /k
"@
    $StartScript | Out-File "$MountDir\Windows\System32\startryara.cmd" -Encoding ASCII

    # Create winpeshl.ini for auto-start
    $WinpeShl = @"
[LaunchApps]
%SYSTEMDRIVE%\Windows\System32\startryara.cmd
"@
    $WinpeShl | Out-File "$MountDir\Windows\System32\winpeshl.ini" -Encoding ASCII

    Write-Host "Step 5: Adding optional components..."
    # Add PowerShell to WinPE (optional, for advanced scripting)
    & dism /Image:$MountDir /Add-Package /PackagePath:"$WinPEPath\$Architecture\WinPE_OCs\WinPE-WMI.cab" 2>$null
    & dism /Image:$MountDir /Add-Package /PackagePath:"$WinPEPath\$Architecture\WinPE_OCs\en-us\WinPE-WMI_en-us.cab" 2>$null
    & dism /Image:$MountDir /Add-Package /PackagePath:"$WinPEPath\$Architecture\WinPE_OCs\WinPE-NetFx.cab" 2>$null
    & dism /Image:$MountDir /Add-Package /PackagePath:"$WinPEPath\$Architecture\WinPE_OCs\WinPE-Scripting.cab" 2>$null
    & dism /Image:$MountDir /Add-Package /PackagePath:"$WinPEPath\$Architecture\WinPE_OCs\WinPE-PowerShell.cab" 2>$null

} finally {
    # Unmount and commit changes
    Write-Host ""
    Write-Host "Step 6: Unmounting and committing changes..."
    & dism /Unmount-Wim /MountDir:$MountDir /Commit
}

# Create ISO
Write-Host ""
Write-Host "Step 7: Creating bootable ISO..."
$IsoPath = "$OutputPath\R-YARA-WinPE.iso"

& cmd /c "MakeWinPEMedia /ISO $OutputPath $IsoPath"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=============================================="
    Write-Host "WinPE image created successfully!"
    Write-Host "=============================================="
    Write-Host ""
    Write-Host "ISO Location: $IsoPath"
    Write-Host "ISO Size:     $([math]::Round((Get-Item $IsoPath).Length / 1MB, 2)) MB"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  1. Write ISO to USB: Use Rufus or similar tool"
    Write-Host "  2. Boot target system from USB"
    Write-Host "  3. R-YARA starts automatically"
    Write-Host ""
} else {
    Write-Warning "ISO creation may have failed. Check $OutputPath\media for files."
}
