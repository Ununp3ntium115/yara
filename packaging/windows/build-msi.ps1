# R-YARA Windows MSI/EXE Installer Builder
#
# Creates Windows installer packages:
#   - MSI installer (Windows Installer)
#   - EXE installer (NSIS-based)
#
# Requirements:
#   - WiX Toolset v4+ (for MSI) - https://wixtoolset.org/
#   - NSIS (for EXE) - https://nsis.sourceforge.io/
#   - Rust toolchain with MSVC target
#
# Usage: .\build-msi.ps1 [-Type <msi|exe|all>] [-Version <version>]

param(
    [string]$Type = "all",
    [string]$Version = "0.1.0",
    [string]$OutputDir = ".\dist"
)

$ErrorActionPreference = "Stop"

$PKG_NAME = "R-YARA"
$PKG_PUBLISHER = "R-YARA Team"
$PKG_URL = "https://github.com/Ununp3ntium115/yara"
$PKG_GUID = "B8E7F6D5-4C3A-2B1A-9F8E-7D6C5B4A3210"

Write-Host "=============================================="
Write-Host "R-YARA Windows Installer Builder"
Write-Host "=============================================="
Write-Host "Type:    $Type"
Write-Host "Version: $Version"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build Rust binaries for Windows
function Build-Binaries {
    Write-Host "Building Windows binaries..."

    $RustDir = Join-Path (Split-Path -Parent $PSScriptRoot) "rust"

    Push-Location $RustDir
    try {
        cargo build --release --package r-yara-cli --package r-yara-pyro --target x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) { throw "Cargo build failed" }

        $TargetDir = "target\x86_64-pc-windows-msvc\release"

        Copy-Item "$TargetDir\r-yara-cli.exe" "$OutputDir\r-yara.exe" -Force
        Copy-Item "$TargetDir\r-yara-pyro.exe" "$OutputDir\r-yara-server.exe" -Force
    } finally {
        Pop-Location
    }

    Write-Host "Binaries built successfully"
}

# Build MSI installer using WiX
function Build-MSI {
    Write-Host ""
    Write-Host "Building MSI installer..."

    # Check for WiX
    $WixPath = Get-Command wix -ErrorAction SilentlyContinue
    if (-not $WixPath) {
        # Try dotnet tool
        $WixPath = Get-Command dotnet-wix -ErrorAction SilentlyContinue
        if (-not $WixPath) {
            Write-Warning "WiX Toolset not found. Install with: dotnet tool install --global wix"
            return
        }
    }

    $WxsFile = "$OutputDir\r-yara.wxs"

    # Create WiX source file
    $WxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
    <Package Name="$PKG_NAME"
             Version="$Version"
             Manufacturer="$PKG_PUBLISHER"
             UpgradeCode="$PKG_GUID"
             Language="1033"
             Codepage="1252">

        <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />

        <MediaTemplate EmbedCab="yes" />

        <Feature Id="ProductFeature" Title="R-YARA Scanner" Level="1">
            <ComponentGroupRef Id="ProductComponents" />
        </Feature>

        <StandardDirectory Id="ProgramFiles64Folder">
            <Directory Id="INSTALLFOLDER" Name="R-YARA">
                <Directory Id="BinFolder" Name="bin" />
                <Directory Id="RulesFolder" Name="rules" />
                <Directory Id="DataFolder" Name="data" />
            </Directory>
        </StandardDirectory>

        <ComponentGroup Id="ProductComponents" Directory="BinFolder">
            <Component Id="RYaraExe" Guid="{B8E7F6D5-4C3A-2B1A-9F8E-7D6C5B4A3211}">
                <File Id="RYara" Source="$OutputDir\r-yara.exe" KeyPath="yes" />
            </Component>
            <Component Id="RYaraServerExe" Guid="{B8E7F6D5-4C3A-2B1A-9F8E-7D6C5B4A3212}">
                <File Id="RYaraServer" Source="$OutputDir\r-yara-server.exe" KeyPath="yes" />
            </Component>
            <Component Id="PathEnv" Guid="{B8E7F6D5-4C3A-2B1A-9F8E-7D6C5B4A3213}">
                <Environment Id="PATH" Name="PATH" Value="[BinFolder]" Permanent="no" Part="last" Action="set" System="yes" />
            </Component>
        </ComponentGroup>

    </Package>
</Wix>
"@

    $WxsContent | Out-File $WxsFile -Encoding UTF8

    # Build MSI
    $MsiFile = "$OutputDir\R-YARA-$Version-x64.msi"

    & wix build $WxsFile -o $MsiFile

    if (Test-Path $MsiFile) {
        Write-Host "MSI installer created: $MsiFile"
        Write-Host "Size: $([math]::Round((Get-Item $MsiFile).Length / 1MB, 2)) MB"
    }
}

# Build EXE installer using NSIS
function Build-EXE {
    Write-Host ""
    Write-Host "Building EXE installer..."

    # Check for NSIS
    $NsisPath = Get-Command makensis -ErrorAction SilentlyContinue
    if (-not $NsisPath) {
        $NsisPath = "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
        if (-not (Test-Path $NsisPath)) {
            $NsisPath = "${env:ProgramFiles}\NSIS\makensis.exe"
        }
    }

    if (-not (Test-Path $NsisPath)) {
        Write-Warning "NSIS not found. Download from: https://nsis.sourceforge.io/"
        return
    }

    $NsiFile = "$OutputDir\r-yara.nsi"

    # Create NSIS script
    $NsiContent = @"
!include "MUI2.nsh"
!include "FileFunc.nsh"

; Installer attributes
Name "$PKG_NAME"
OutFile "$OutputDir\R-YARA-$Version-Setup.exe"
InstallDir "`$PROGRAMFILES64\R-YARA"
RequestExecutionLevel admin

; Modern UI settings
!define MUI_ABORTWARNING
!define MUI_ICON "r-yara.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath "`$INSTDIR\bin"
    File "$OutputDir\r-yara.exe"
    File "$OutputDir\r-yara-server.exe"

    SetOutPath "`$INSTDIR\rules"
    ; Sample rules would go here

    SetOutPath "`$INSTDIR"

    ; Create uninstaller
    WriteUninstaller "`$INSTDIR\Uninstall.exe"

    ; Add to PATH
    EnVar::AddValue "PATH" "`$INSTDIR\bin"

    ; Create Start Menu shortcuts
    CreateDirectory "`$SMPROGRAMS\R-YARA"
    CreateShortcut "`$SMPROGRAMS\R-YARA\R-YARA Scanner.lnk" "`$INSTDIR\bin\r-yara.exe"
    CreateShortcut "`$SMPROGRAMS\R-YARA\R-YARA Server.lnk" "`$INSTDIR\bin\r-yara-server.exe" "server"
    CreateShortcut "`$SMPROGRAMS\R-YARA\Uninstall.lnk" "`$INSTDIR\Uninstall.exe"

    ; Registry for Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA" "DisplayName" "$PKG_NAME"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA" "UninstallString" "`$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA" "Publisher" "$PKG_PUBLISHER"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA" "DisplayVersion" "$Version"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA" "URLInfoAbout" "$PKG_URL"
SectionEnd

Section "Uninstall"
    ; Remove files
    Delete "`$INSTDIR\bin\r-yara.exe"
    Delete "`$INSTDIR\bin\r-yara-server.exe"
    Delete "`$INSTDIR\Uninstall.exe"
    RMDir "`$INSTDIR\bin"
    RMDir "`$INSTDIR\rules"
    RMDir "`$INSTDIR"

    ; Remove from PATH
    EnVar::DeleteValue "PATH" "`$INSTDIR\bin"

    ; Remove Start Menu
    Delete "`$SMPROGRAMS\R-YARA\*.lnk"
    RMDir "`$SMPROGRAMS\R-YARA"

    ; Remove registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\R-YARA"
SectionEnd
"@

    $NsiContent | Out-File $NsiFile -Encoding UTF8

    # Create placeholder icon and license if they don't exist
    if (-not (Test-Path "$OutputDir\r-yara.ico")) {
        # Create a simple placeholder
        Write-Host "Note: Using placeholder icon. Replace r-yara.ico for custom icon."
    }

    if (-not (Test-Path "$OutputDir\LICENSE.txt")) {
        "MIT License - R-YARA Scanner`n`nSee $PKG_URL for full license." | Out-File "$OutputDir\LICENSE.txt"
    }

    # Build EXE
    & $NsisPath $NsiFile

    $ExeFile = "$OutputDir\R-YARA-$Version-Setup.exe"
    if (Test-Path $ExeFile) {
        Write-Host "EXE installer created: $ExeFile"
        Write-Host "Size: $([math]::Round((Get-Item $ExeFile).Length / 1MB, 2)) MB"
    }
}

# Main execution
try {
    # Build binaries if they don't exist
    if (-not (Test-Path "$OutputDir\r-yara.exe") -or -not (Test-Path "$OutputDir\r-yara-server.exe")) {
        Build-Binaries
    }

    switch ($Type) {
        "msi" { Build-MSI }
        "exe" { Build-EXE }
        "all" {
            Build-MSI
            Build-EXE
        }
        default {
            Write-Error "Unknown type: $Type. Use: msi, exe, or all"
        }
    }

    Write-Host ""
    Write-Host "=============================================="
    Write-Host "Build complete!"
    Write-Host "=============================================="
    Get-ChildItem $OutputDir -Filter "*.msi","*.exe" | ForEach-Object {
        Write-Host "  $($_.Name) - $([math]::Round($_.Length / 1MB, 2)) MB"
    }

} catch {
    Write-Error "Build failed: $_"
    exit 1
}
