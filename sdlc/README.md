# YARA Cryptex - SDLC Framework

## 🎯 Comprehensive SDLC with Security, Simplification, and UA Testing

This directory contains the complete SDLC framework for iterative improvement of the YARA Cryptex system.

## 📦 Components

### 1. UA Testing Framework (`ua_testing_framework.py`)
- Complete UI interaction logging
- Selenium-based browser automation
- Screenshot capture
- Console log capture
- API endpoint testing
- Full interaction history

### 2. Security Audit (`security_audit.py`)
- Rust dependency auditing (cargo-audit)
- Python code security analysis
- Configuration file auditing
- Vulnerability detection
- Security report generation

### 3. Code Simplification (`code_simplification.py`)
- Code complexity analysis
- Redundancy detection
- Simplification opportunities
- Maintainability metrics

### 4. Iterative SDLC Controller (`iterative_sdlc.py`)
- Complete SDLC cycle management
- Automated workflow
- Report generation
- Multi-cycle support

## 🚀 Quick Start

### Install Dependencies
```powershell
pip install -r sdlc/requirements.txt
```

### Run Complete SDLC Cycle
```powershell
.\sdlc\run_sdlc_cycle.ps1
```

### Run Individual Components

#### Security Audit
```powershell
python sdlc/security_audit.py
```

#### Code Simplification
```powershell
python sdlc/code_simplification.py
```

#### UA Testing
```powershell
python sdlc/ua_testing_framework.py
```

#### Complete SDLC Cycle
```powershell
python sdlc/iterative_sdlc.py
```

## 📊 Output

### Logs
- `sdlc/security_audit.log` - Security audit logs
- `sdlc/code_simplification.log` - Code analysis logs
- `ua_logs/ua_session_*.log` - UA testing logs

### Reports
- `sdlc/security_audit_*.json` - Security audit reports
- `sdlc/code_simplification_*.json` - Code simplification reports
- `sdlc/cycles/cycle_*.json` - SDLC cycle reports
- `ua_logs/interactions_*.json` - Interaction logs
- `ua_logs/session_report_*.json` - Session reports

### Screenshots
- `ua_logs/screenshots/` - All UI screenshots

## 🔍 What Gets Logged

### UI Interactions
- All clicks
- All text input
- All navigation
- All element interactions
- Console logs
- Browser performance logs

### Commands
- All CLI commands executed
- Command output
- Exit codes

### API Calls
- All API endpoints called
- Request/response data
- Status codes

### System Events
- Service starts/stops
- Build processes
- Test executions

## 🔄 Iterative Improvement

The SDLC cycle runs:
1. Security Audit
2. Code Simplification Analysis
3. Build System
4. Start Services
5. UA Testing
6. Generate Reports

Each cycle produces reports that can be used to improve the system iteratively.

## 📝 Windows 11 Specific

The framework is designed for Windows 11:
- PowerShell scripts
- Windows-specific paths
- Chrome WebDriver for UI testing
- Windows service management

## ✅ Verification

After each cycle:
- Review security audit reports
- Review code simplification reports
- Review UA test results
- Review screenshots
- Make improvements
- Run next cycle

---

**Status**: Ready for iterative SDLC cycles

