# YARA Cryptex - SDLC Workflow Guide

## 🔄 Iterative SDLC Process

### Overview

The SDLC framework provides a complete iterative improvement cycle:
1. **Security Audit** - Find and fix vulnerabilities
2. **Code Simplification** - Reduce complexity and redundancy
3. **Build** - Ensure system builds successfully
4. **Start Services** - Launch API and frontend
5. **UA Testing** - Test with full interaction logging
6. **Review & Improve** - Analyze results and make improvements
7. **Repeat** - Run next cycle

## 🚀 Running SDLC Cycles

### Quick Start
```powershell
.\sdlc\run_sdlc_cycle.ps1
```

### Manual Cycle
```powershell
# Step 1: Security Audit
python sdlc/security_audit.py

# Step 2: Code Simplification
python sdlc/code_simplification.py

# Step 3: Build
cd rust
cargo build --release --workspace
cd ..

# Step 4: Start Services
.\start_services.ps1

# Step 5: UA Testing
python sdlc/ua_testing_framework.py

# Step 6: Review Reports
# Check sdlc/ and ua_logs/ directories
```

## 📊 What Gets Logged

### UI Interactions
- ✅ Every click
- ✅ Every text input
- ✅ Every navigation
- ✅ Every element interaction
- ✅ Browser console logs
- ✅ Performance metrics
- ✅ Screenshots (before/after actions)

### Commands
- ✅ All CLI commands
- ✅ Command output
- ✅ Exit codes
- ✅ Execution time

### API Calls
- ✅ All API requests
- ✅ Request/response data
- ✅ Status codes
- ✅ Response times

### System Events
- ✅ Service starts
- ✅ Service stops
- ✅ Build processes
- ✅ Test executions
- ✅ Errors and warnings

## 🔍 Reviewing Results

### After Each Cycle

1. **Review Security Audit**
   - Check `sdlc/security_audit_*.json`
   - Fix vulnerabilities
   - Update dependencies

2. **Review Code Simplification**
   - Check `sdlc/code_simplification_*.json`
   - Refactor complex code
   - Remove redundancy

3. **Review UA Test Results**
   - Check `ua_logs/interactions_*.json`
   - Review screenshots
   - Check console logs
   - Verify UI functionality

4. **Review Cycle Report**
   - Check `sdlc/cycles/cycle_*.json`
   - See what succeeded/failed
   - Plan improvements

## 🔄 Iterative Improvement

### Cycle 1: Baseline
- Run initial audit
- Establish baseline metrics
- Identify issues

### Cycle 2-N: Improvements
- Fix issues from previous cycle
- Verify improvements
- Continue refinement

### Continuous
- Run cycles regularly
- Track improvements
- Maintain quality

## 📝 Windows 11 Specific

### Prerequisites
- Python 3.8+
- Chrome browser (for Selenium)
- ChromeDriver (auto-downloaded)
- Rust toolchain
- Node.js (for frontend)

### Setup
```powershell
# Install Python dependencies
pip install -r sdlc/requirements.txt

# Install ChromeDriver (if needed)
# Selenium will attempt to download automatically
```

## ✅ Success Criteria

### Security
- No high-severity vulnerabilities
- Dependencies up to date
- No hardcoded secrets

### Code Quality
- Complexity < 10 per function
- No redundant code
- Maintainable structure

### UI Functionality
- All pages load
- All interactions work
- No console errors
- Screenshots show correct UI

## 🎯 Next Steps

1. Run first SDLC cycle
2. Review all reports
3. Make improvements
4. Run next cycle
5. Iterate until satisfied

---

**Ready for iterative SDLC cycles!**

