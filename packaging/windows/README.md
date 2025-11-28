# R-YARA Windows Integration

Scripts and configuration for integrating R-YARA with Windows environments:

- **Windows PE (WinPE)** - Bootable Windows environment with R-YARA
- **Windows ADK** - Windows Assessment and Deployment Kit integration
- **Windows Server** - Service installation and management

## Windows PE with Windows ADK

### Prerequisites

1. Install Windows ADK from Microsoft
2. Install WinPE add-on for Windows ADK

### Creating WinPE with R-YARA

```powershell
# Run as Administrator
.\create-winpe.ps1
```

This creates a bootable WinPE image with R-YARA pre-installed.

### Manual Integration

1. Create WinPE environment:
   ```cmd
   copype amd64 C:\WinPE_amd64
   ```

2. Mount boot.wim:
   ```cmd
   dism /Mount-Wim /WimFile:C:\WinPE_amd64\media\sources\boot.wim /index:1 /MountDir:C:\WinPE_amd64\mount
   ```

3. Copy R-YARA files:
   ```cmd
   copy r-yara.exe C:\WinPE_amd64\mount\Windows\System32\
   copy r-yara-server.exe C:\WinPE_amd64\mount\Windows\System32\
   ```

4. Create startup script (winpeshl.ini):
   ```ini
   [LaunchApps]
   %SYSTEMDRIVE%\Windows\System32\wpeinit.exe
   %SYSTEMDRIVE%\Windows\System32\r-yara-server.exe, server --port 8080
   ```

5. Unmount and commit:
   ```cmd
   dism /Unmount-Wim /MountDir:C:\WinPE_amd64\mount /Commit
   ```

6. Create ISO:
   ```cmd
   MakeWinPEMedia /ISO C:\WinPE_amd64 C:\WinPE_amd64\R-YARA-WinPE.iso
   ```

## Windows Service Installation

Install R-YARA as a Windows service:

```powershell
.\install-service.ps1
```

This registers R-YARA Fire Hydrant API as a Windows service that:
- Starts automatically at boot
- Runs under LocalSystem account
- Listens on port 8080

## Configuration

Default configuration file: `%ProgramData%\R-YARA\config.json`

```json
{
  "api": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "scanner": {
    "rules_dir": "%ProgramData%\\R-YARA\\rules",
    "data_dir": "%ProgramData%\\R-YARA\\data"
  }
}
```

## Cross-Compilation

To build R-YARA for Windows from Linux:

```bash
# Install cross-compilation tools
rustup target add x86_64-pc-windows-gnu
sudo apt-get install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```
