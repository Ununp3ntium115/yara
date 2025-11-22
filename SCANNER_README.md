# YARA System Scanner

This scanner integrates YARA with the Yara-Rules repository to scan your system for malware, webshells, exploits, and other threats.

## Setup

1. **Python Requirements**: Python 3.x with yara-python package (already installed)

2. **Rules**: The scanner uses the Yara-Rules repository (already cloned in `yara-rules/`)

## Usage

### PowerShell (Recommended for Windows)

```powershell
# Scan a directory with all rules
.\scan.ps1 -Directory "C:\Path\To\Scan"

# Scan with specific rule type
.\scan.ps1 -Directory "C:\Users\YourName\Downloads" -RulesType malware

# Scan and save results to JSON
.\scan.ps1 -Directory "C:\temp" -RulesType webshells -OutputFile "results.json"

# Scan without recursion (only top-level files)
.\scan.ps1 -Directory "C:\temp" -NoRecursive
```

### Python (Direct)

```bash
# Scan with all rules
python yara_scanner.py -d "C:\Path\To\Scan"

# Scan with specific rules
python yara_scanner.py -r yara-rules/malware_index.yar -d "C:\temp"

# Scan specific file types only
python yara_scanner.py -d "C:\temp" -e .exe .dll .pdf

# Save results to JSON
python yara_scanner.py -d "C:\temp" -o scan_results.json
```

## Available Rule Types

- **all** - All available rules (comprehensive scan)
- **malware** - Malware detection rules
- **webshells** - Web shell detection
- **cve** - CVE exploit detection
- **packers** - Packed executable detection
- **maldocs** - Malicious document detection
- **capabilities** - Behavioral capability detection

## Safety Notes

1. **Performance**: Scanning large directories can take time. Start with smaller directories.

2. **False Positives**: YARA rules may produce false positives. Review matches carefully.

3. **File Size**: The scanner skips files larger than 100MB to prevent slowdowns.

4. **Permissions**: Run with appropriate permissions to access files you want to scan.

## Example Workflow

1. **Test scan on safe directory**:
   ```powershell
   .\scan.ps1 -Directory "E:\GitRepos\Yara\yara\tests" -RulesType malware
   ```

2. **Scan Downloads folder**:
   ```powershell
   .\scan.ps1 -Directory "C:\Users\YourName\Downloads" -RulesType malware -OutputFile "downloads_scan.json"
   ```

3. **Full system scan** (WARNING: Very slow):
   ```powershell
   .\scan.ps1 -Directory "C:\" -RulesType malware -OutputFile "full_scan.json"
   ```

## Output

The scanner provides:
- Real-time progress updates
- Match details (rule name, tags, metadata)
- Summary statistics
- Optional JSON output for further analysis

## Troubleshooting

**PowerShell Execution Policy Error**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Python not found**:
Ensure Python is in your PATH or use the full path to python.exe

**Rules file not found**:
Make sure you're running the scanner from the YARA project directory where `yara-rules/` exists.
