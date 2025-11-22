# SDLC Framework - Quick Start

## 🚀 Quick Start for Windows 11

### Option 1: Complete UA Session (Recommended)
```powershell
.\sdlc\start_ua_session.ps1
```

This will:
1. Build the system
2. Start API server
3. Start frontend
4. Run UA tests with full logging
5. Show results

### Option 2: SDLC Cycle Runner
```powershell
.\sdlc\windows11_ua_runner.ps1 -Cycles 1
```

This runs a complete SDLC cycle:
1. Security audit
2. Code simplification
3. Build
4. Start services
5. UA testing

### Option 3: Individual Components

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

## 📊 What Gets Logged

### Every UI Interaction
- ✅ Clicks
- ✅ Text input
- ✅ Navigation
- ✅ Form submissions
- ✅ Console logs
- ✅ Errors

### Screenshots
- ✅ Before each action
- ✅ After each action
- ✅ On errors
- ✅ Final state

### Commands
- ✅ All CLI commands
- ✅ Output and exit codes

### API Calls
- ✅ All requests
- ✅ Responses
- ✅ Status codes

## 📁 Output Locations

### Logs
- `ua_logs/ua_session_*.log` - Session logs
- `ua_logs/interactions_*.json` - Interaction logs
- `sdlc/security_audit.log` - Security audit logs
- `sdlc/code_simplification.log` - Code analysis logs

### Reports
- `sdlc/security_audit_*.json` - Security reports
- `sdlc/code_simplification_*.json` - Code analysis reports
- `sdlc/cycles/cycle_*.json` - SDLC cycle reports

### Screenshots
- `ua_logs/screenshots/` - All UI screenshots

## 🔄 Iterative Improvement

1. Run cycle
2. Review reports
3. Make improvements
4. Run next cycle
5. Repeat

## ✅ Prerequisites

- Python 3.8+
- Chrome browser
- Rust toolchain (for building)
- Node.js (for frontend)

## 🎯 Next Steps

1. Install dependencies: `pip install -r sdlc/requirements.txt`
2. Run first cycle: `.\sdlc\start_ua_session.ps1`
3. Review results
4. Make improvements
5. Run next cycle

---

**Ready for iterative SDLC cycles!**

