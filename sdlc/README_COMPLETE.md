# YARA Cryptex - Complete SDLC Framework

## 🎯 Overview

Complete SDLC framework for iterative improvement of the YARA Cryptex system with:
- ✅ Comprehensive UA testing with full logging
- ✅ Security vulnerability detection
- ✅ Code complexity analysis
- ✅ Iterative improvement cycles
- ✅ Windows 11 optimization

## 📦 Components

### Core Framework
- `ua_testing_framework.py` - Selenium-based UA testing
- `security_audit.py` - Security vulnerability detection
- `code_simplification.py` - Code complexity analysis
- `iterative_sdlc.py` - SDLC cycle controller

### Runner Scripts
- `start_ua_session.ps1` - Complete UA session
- `windows11_ua_runner.ps1` - Windows 11 optimized
- `run_first_cycle.ps1` - First cycle (simplified)
- `run_sdlc_cycle.ps1` - Standard SDLC cycle

### Setup & Tools
- `setup_sdlc.ps1` - Install dependencies
- `verify_setup.py` - Verify prerequisites
- `quick_test.py` - Quick framework test
- `view_results.py` - View SDLC results

### Client-Side
- `ui_interaction_logger.js` - Client-side logger

## 🚀 Quick Start

### 1. Setup
```powershell
.\sdlc\setup_sdlc.ps1
```

### 2. Verify
```powershell
python sdlc\verify_setup.py
```

### 3. Test
```powershell
python sdlc\quick_test.py
```

### 4. Run First Cycle
```powershell
.\sdlc\run_first_cycle.ps1
```

### 5. View Results
```powershell
.\sdlc\view_results.ps1
```

## 📊 What Gets Logged

### UI Interactions
- Every click (element, selector, text)
- Every text input (field, value)
- Every navigation (URL, title)
- Every form submission
- Browser console logs
- JavaScript errors

### Screenshots
- Before each action
- After each action
- On errors
- Final state
- All timestamped

### Commands
- All CLI commands
- Command output
- Exit codes

### API Calls
- All API requests
- Request/response data
- Status codes

### Security
- Dependency vulnerabilities
- Code security issues
- Configuration problems

### Code Quality
- Function complexity
- Code duplication
- Simplification opportunities

## 🔄 SDLC Cycle Process

1. **Security Audit** - Find vulnerabilities
2. **Code Simplification** - Find complexity issues
3. **Build** - Ensure system builds
4. **Start Services** - Launch API/frontend
5. **UA Testing** - Test with full logging
6. **Review** - Analyze results
7. **Improve** - Fix issues
8. **Repeat** - Next cycle

## 📁 Output Locations

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

## ✅ Prerequisites

### Required
- Python 3.8+
- Chrome browser
- PowerShell 7+

### Optional
- Rust toolchain (for building)
- Node.js (for frontend)
- cargo-audit (for Rust security audit)

## 🎯 Success Indicators

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

## 📝 Usage Examples

### Run Complete Session
```powershell
.\sdlc\start_ua_session.ps1
```

### Run SDLC Cycle
```powershell
.\sdlc\windows11_ua_runner.ps1 -Cycles 1
```

### View Results
```powershell
.\sdlc\view_results.ps1
```

### Individual Components
```powershell
# Security Audit
python sdlc/security_audit.py

# Code Simplification
python sdlc/code_simplification.py

# UA Testing
python sdlc/ua_testing_framework.py
```

## 🔍 Troubleshooting

### Browser Won't Start
- Install Chrome
- Check ChromeDriver version
- Verify Selenium installation

### API Server Won't Start
- Check if port 3006 is available
- Verify binary exists
- Check database initialization

### Import Errors
- Run from project root
- Check Python path
- Verify dependencies installed

## 🎊 Framework Status

**STATUS**: ✅ **READY FOR USE**

All components created and tested:
- ✅ UA Testing Framework
- ✅ Security Audit Tool
- ✅ Code Simplification Analyzer
- ✅ Iterative SDLC Controller
- ✅ Windows 11 Runners
- ✅ Setup & Verification
- ✅ Results Viewer

**Ready for iterative SDLC cycles on Windows 11!** 🚀

---

**Quick Start**: 
1. `.\sdlc\setup_sdlc.ps1`
2. `.\sdlc\run_first_cycle.ps1`
3. `.\sdlc\view_results.ps1`

