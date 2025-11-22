# YARA Scanner Setup Session Notes

## Date: November 14, 2025

## What We Accomplished

### 1. Repository Setup
- Imported YARA source code repository (version 4.5.5)
- Cloned Yara-Rules repository into `yara-rules/` subdirectory
- Created comprehensive CLAUDE.md documentation for the YARA codebase

### 2. Installation
- System: Windows with Python 3.11.9
- Installed: yara-python 4.5.4 (already present on system)
- Note: Building from source not possible due to missing build tools (autoreconf, gcc, make)
- Solution: Using pre-compiled yara-python package instead

### 3. Scanner Development
Created three main files:

#### yara_scanner.py
- Python-based YARA scanner
- Features:
  - Scans directories recursively or non-recursively
  - Filters by file extensions
  - Skips files > 100MB
  - JSON output support
  - Progress reporting
  - Match details with rules, tags, and metadata

#### scan.ps1
- PowerShell wrapper for Windows
- Simplifies usage with parameter validation
- Supports rule type selection (malware, webshells, cve, etc.)
- Color-coded output

#### SCANNER_README.md
- Complete usage documentation
- Examples for common scanning scenarios
- Safety notes and troubleshooting

### 4. Current Issue

**Problem**: Some YARA rules in the Yara-Rules repository reference the `cuckoo` module which isn't available by default.

**Error Example**:
```
yara-rules/./malware/MALW_AZORULT.yar(23): invalid field name "sync"
```

**Affected Rule**: Uses `cuckoo.sync.mutex()` in condition

**Solutions** (choose one):
1. Filter out problematic rules
2. Comment out cuckoo-dependent conditions
3. Build YARA with cuckoo module enabled
4. Create a curated rule set without cuckoo dependencies

## Next Steps (After Reboot)

### Immediate Tasks

1. **Fix Rule Compatibility**
   ```bash
   cd /e/GitRepos/Yara/yara
   # Option A: Create a filtered rule index without cuckoo dependencies
   # Option B: Comment out cuckoo references in problematic rules
   ```

2. **Create Working Rule Set**
   ```bash
   # Test with simpler rule categories first:
   python yara_scanner.py -r yara-rules/webshells_index.yar -d tests
   python yara_scanner.py -r yara-rules/packers_index.yar -d tests
   ```

3. **PowerShell Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Recommended First Scan

Safe test scan on small directory:
```powershell
.\scan.ps1 -Directory "C:\Users\xservera\Downloads" -RulesType webshells
```

### Full System Scan Command

Once rules are working:
```powershell
# Scan Downloads folder
.\scan.ps1 -Directory "C:\Users\xservera\Downloads" -RulesType malware -OutputFile "downloads_scan.json"

# Scan specific directories
.\scan.ps1 -Directory "C:\Windows\Temp" -RulesType malware -OutputFile "temp_scan.json"

# Full C: drive scan (WARNING: VERY SLOW - hours)
.\scan.ps1 -Directory "C:\" -RulesType malware -OutputFile "full_system_scan.json"
```

## File Locations

```
E:\GitRepos\Yara\yara\
├── yara_scanner.py          # Main Python scanner
├── scan.ps1                 # PowerShell wrapper
├── SCANNER_README.md        # User documentation
├── SESSION_NOTES.md         # This file
├── CLAUDE.md                # Codebase documentation for Claude
├── yara-rules/              # YARA rules repository
│   ├── index.yar            # All rules (has cuckoo issues)
│   ├── malware_index.yar    # Malware rules (has cuckoo issues)
│   ├── webshells_index.yar  # Webshell rules
│   ├── cve_rules_index.yar  # CVE exploit rules
│   ├── packers_index.yar    # Packer detection
│   └── ...
└── tests/                   # YARA test files
```

## Known Issues

1. **Cuckoo Module Dependencies**: Some malware rules require the cuckoo module
   - Files affected: malware/MALW_AZORULT.yar (and potentially others)
   - Workaround needed: Filter or modify rules

2. **No Build Environment**: Cannot build YARA from source on this Windows system
   - Missing: autoreconf, gcc, make, Visual Studio
   - Current solution: Use yara-python package

## System Information

- OS: Windows (win32)
- Python: 3.11.9
- yara-python: 4.5.4
- Working Directory: E:\GitRepos\Yara\yara
- Not a git repository (yet)

## Quick Recovery Commands

After reboot, to continue:

```bash
# Navigate to project
cd /e/GitRepos/Yara/yara

# Test Python YARA
python -c "import yara; print('YARA version:', yara.__version__)"

# List available rule indices
ls yara-rules/*_index.yar

# Try a simple rule set (no cuckoo dependencies)
python yara_scanner.py -r yara-rules/packers_index.yar -d tests --no-recursive
```

## Todo for Next Session

- [ ] Fix or filter rules with cuckoo module dependencies
- [ ] Create a curated "safe" rule index file
- [ ] Test scan on Downloads folder
- [ ] Test scan on Temp folders
- [ ] Document scanning results
- [ ] Consider creating automated scheduled scans
- [ ] Set up alerts for matches
