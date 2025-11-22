# YARA Cryptex - SDLC Framework Master Guide

## 🎯 Complete SDLC Framework for Iterative Improvement

### Status: ✅ **PRODUCTION READY**

**Version**: 1.0  
**Date**: 2025  
**Platform**: Windows 11  
**Total Files**: 25

---

## 📦 Framework Overview

### Purpose
Complete SDLC framework for iterative improvement of the YARA Cryptex system with:
- Comprehensive UA testing with full logging
- Security vulnerability detection
- Code complexity analysis
- Iterative improvement cycles
- Windows 11 optimization

### Key Features
- ✅ **Complete Logging**: Every UI interaction, command, API call
- ✅ **Screenshot Capture**: Before/after every action
- ✅ **Security Analysis**: Automated vulnerability detection
- ✅ **Code Quality**: Complexity and redundancy analysis
- ✅ **Iterative Cycles**: Automated SDLC workflow
- ✅ **Results Viewer**: Easy analysis of results

---

## 🚀 Quick Start Guide

### First Time Setup

1. **Install Dependencies**
   ```powershell
   .\sdlc\setup_sdlc.ps1
   ```
   This installs: selenium, requests, radon, bandit

2. **Verify Setup**
   ```powershell
   python sdlc\verify_setup.py
   ```

3. **Quick Test**
   ```powershell
   python sdlc\quick_test.py
   ```

### Running SDLC Cycles

#### Option 1: First Cycle (Recommended for First Time)
```powershell
.\sdlc\run_first_cycle.ps1
```
- Simplified workflow
- Step-by-step execution
- Results summary

#### Option 2: Complete Session
```powershell
.\sdlc\start_ua_session.ps1
```
- Builds system
- Starts services
- Runs UA tests
- Shows results

#### Option 3: Multiple Cycles
```powershell
.\sdlc\windows11_ua_runner.ps1 -Cycles 3
```
- Runs multiple SDLC cycles
- Compares results
- Iterative improvement

### Viewing Results

```powershell
.\sdlc\view_results.ps1
```

Shows:
- Security audit results
- Code simplification results
- UA interaction logs
- Screenshots
- Cycle reports

---

## 📊 What Gets Logged

### UI Interactions ✅
- Every click (element, selector, text)
- Every text input (field, value)
- Every navigation (URL, title)
- Every form submission
- Browser console logs
- JavaScript errors
- Performance metrics

### Screenshots ✅
- Before each action
- After each action
- On errors
- Final state
- All timestamped

### Commands ✅
- All CLI commands executed
- Command output
- Exit codes
- Execution time

### API Calls ✅
- All API requests
- Request/response data
- Status codes
- Response times

### Security ✅
- Dependency vulnerabilities
- Code security issues
- Hardcoded secrets
- Configuration problems

### Code Quality ✅
- Function complexity
- Code duplication
- Simplification opportunities
- Maintainability metrics

---

## 🔄 SDLC Cycle Process

### Complete Cycle Steps

1. **Security Audit**
   - Rust dependency auditing
   - Python code security analysis
   - Configuration file auditing
   - Vulnerability detection

2. **Code Simplification**
   - Code complexity analysis
   - Redundancy detection
   - Simplification opportunities

3. **Build**
   - Build Rust workspace
   - Verify binaries created
   - Check for build errors

4. **Start Services**
   - Start API server
   - Start frontend (if available)
   - Verify services running

5. **UA Testing**
   - Open browser
   - Navigate to pages
   - Test interactions
   - Capture screenshots
   - Log all actions

6. **Review**
   - Analyze security findings
   - Review code complexity
   - Check UI interactions
   - Review screenshots

7. **Improve**
   - Fix security issues
   - Simplify code
   - Fix UI issues
   - Update documentation

8. **Repeat**
   - Run next cycle
   - Verify improvements
   - Continue iteration

---

## 📁 File Structure

```
sdlc/
├── Core Framework/
│   ├── ua_testing_framework.py
│   ├── security_audit.py
│   ├── code_simplification.py
│   └── iterative_sdlc.py
│
├── Runner Scripts/
│   ├── start_ua_session.ps1
│   ├── windows11_ua_runner.ps1
│   ├── run_first_cycle.ps1
│   └── run_sdlc_cycle.ps1
│
├── Setup & Tools/
│   ├── setup_sdlc.ps1
│   ├── verify_setup.py
│   ├── quick_test.py
│   └── view_results.py
│
├── Utilities/
│   ├── cleanup_old_logs.ps1
│   ├── export_results.ps1
│   └── compare_cycles.ps1
│
├── Client-Side/
│   └── ui_interaction_logger.js
│
└── Documentation/
    ├── README.md
    ├── SDLC_WORKFLOW.md
    ├── SDLC_QUICK_START.md
    ├── INTEGRATION_GUIDE.md
    └── README_COMPLETE.md

ua_logs/
├── screenshots/         # All UI screenshots
├── interactions_*.json  # Interaction logs
├── ua_session_*.log     # Session logs
└── session_report_*.json
```

---

## 🛠️ Utilities

### Cleanup Old Logs
```powershell
# Dry run (see what would be deleted)
.\sdlc\cleanup_old_logs.ps1 -DaysOld 30 -DryRun

# Actually delete files older than 30 days
.\sdlc\cleanup_old_logs.ps1 -DaysOld 30
```

### Export Results
```powershell
# Export to default archive
.\sdlc\export_results.ps1

# Export to custom path
.\sdlc\export_results.ps1 -OutputPath "my_results.zip"
```

### Compare Cycles
```powershell
# Compare cycle 1 vs cycle 2
.\sdlc\compare_cycles.ps1 -Cycle1 1 -Cycle2 2
```

---

## ✅ Prerequisites

### Required
- Python 3.8+
- Chrome browser
- PowerShell 7+

### Optional
- Rust toolchain (for building)
- Node.js (for frontend)
- cargo-audit (for Rust security audit)

### Install Dependencies
```powershell
pip install selenium requests radon bandit
```

---

## 🎯 Success Criteria

### Good Cycle
- ✅ All pages load
- ✅ All interactions logged
- ✅ Screenshots captured
- ✅ No critical security issues
- ✅ Code complexity acceptable

### Needs Improvement
- ⚠️ Pages fail to load
- ⚠️ Interactions not captured
- ⚠️ Security vulnerabilities found
- ⚠️ High code complexity

---

## 📝 Usage Examples

### Run Individual Components

#### Security Audit Only
```powershell
python sdlc/security_audit.py
```

#### Code Simplification Only
```powershell
python sdlc/code_simplification.py
```

#### UA Testing Only
```powershell
python sdlc/ua_testing_framework.py
```

### Run Complete SDLC Cycle
```powershell
python sdlc/iterative_sdlc.py
```

---

## 🔍 Troubleshooting

### Missing Dependencies
```powershell
pip install selenium requests radon bandit
```

### Browser Won't Start
- Install Chrome browser
- Check ChromeDriver version
- Verify Selenium installation

### API Server Won't Start
- Check if port 3006 is available
- Verify binary exists: `rust\cryptex-api\target\release\cryptex-api.exe`
- Check database initialization

### Import Errors
- Run from project root directory
- Check Python path
- Verify dependencies installed

### No Results Generated
- Run SDLC cycle first: `.\sdlc\run_first_cycle.ps1`
- Check that services started
- Verify browser opened

---

## 📊 Output Locations

### Logs
- `ua_logs/ua_session_*.log` - Session logs
- `ua_logs/interactions_*.json` - Interaction logs
- `sdlc/security_audit.log` - Security audit logs
- `sdlc/code_simplification.log` - Code analysis logs

### Reports
- `sdlc/security_audit_*.json` - Security reports
- `sdlc/code_simplification_*.json` - Code analysis
- `sdlc/cycles/cycle_*.json` - SDLC cycle reports
- `ua_logs/session_report_*.json` - Session reports

### Screenshots
- `ua_logs/screenshots/` - All UI screenshots

---

## 🔄 Iterative Improvement Workflow

### Cycle 1: Baseline
1. Run first cycle
2. Review all reports
3. Identify issues
4. Document findings

### Cycle 2-N: Improvements
1. Fix issues from previous cycle
2. Run cycle again
3. Verify improvements
4. Continue refinement

### Continuous
1. Run cycles regularly
2. Track improvements
3. Maintain quality
4. Document changes

---

## 🎊 Framework Status

**STATUS**: ✅ **PRODUCTION READY**

All components created and tested:
- ✅ UA Testing Framework
- ✅ Security Audit Tool
- ✅ Code Simplification Analyzer
- ✅ Iterative SDLC Controller
- ✅ Windows 11 Runners
- ✅ Setup & Verification
- ✅ Results Viewer
- ✅ Utilities
- ✅ Complete Documentation

**Ready for iterative SDLC cycles on Windows 11!** 🚀

---

## 📚 Documentation

- `SDLC_QUICK_START.md` - Quick start guide
- `SDLC_WORKFLOW.md` - Detailed workflow
- `INTEGRATION_GUIDE.md` - Integration guide
- `SDLC_STATUS.md` - Status summary
- `SDLC_COMPLETE.md` - Completion summary
- `SDLC_FRAMEWORK_FINAL.md` - Final summary

---

## 🚀 Next Steps

1. **Setup**: `.\sdlc\setup_sdlc.ps1`
2. **Verify**: `python sdlc\verify_setup.py`
3. **Test**: `python sdlc\quick_test.py`
4. **Run**: `.\sdlc\run_first_cycle.ps1`
5. **View**: `.\sdlc\view_results.ps1`
6. **Improve**: Fix issues found
7. **Repeat**: Run next cycle

---

**Quick Start**: `.\sdlc\setup_sdlc.ps1` → `.\sdlc\run_first_cycle.ps1`

