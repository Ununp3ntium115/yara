# SDLC Framework - Integration Guide

## 🔗 Integrating with Existing System

### Frontend UI Logging

The PYRO Platform frontend already has UA logging components:
- `uaLogger.js` - UA logging service
- `UASessionManager.svelte` - Session management component

The SDLC framework enhances this with:
- Server-side interaction logging
- Screenshot capture
- Automated testing
- Security and code analysis

## 🚀 Running Your First SDLC Cycle

### Step 1: Install Dependencies
```powershell
pip install -r sdlc/requirements.txt
```

### Step 2: Run Complete Session
```powershell
.\sdlc\start_ua_session.ps1
```

This will:
1. ✅ Build the system
2. ✅ Start API server
3. ✅ Start frontend (if available)
4. ✅ Run automated UA tests
5. ✅ Capture all interactions
6. ✅ Take screenshots
7. ✅ Generate reports

### Step 3: Review Results

Check these locations:
- `ua_logs/interactions_*.json` - All UI interactions
- `ua_logs/screenshots/` - All screenshots
- `ua_logs/ua_session_*.log` - Session logs
- `sdlc/security_audit_*.json` - Security findings
- `sdlc/code_simplification_*.json` - Code analysis

## 🔄 Iterative Improvement Process

### Cycle 1: Baseline
1. Run: `.\sdlc\start_ua_session.ps1`
2. Review all reports
3. Identify issues
4. Document findings

### Cycle 2-N: Improvements
1. Fix issues from previous cycle
2. Run cycle again
3. Verify improvements
4. Continue refinement

## 📊 What You'll See

### During Testing
- Browser opens automatically
- Pages navigate automatically
- Interactions are logged
- Screenshots are captured
- Console logs are captured

### After Testing
- Complete interaction log (JSON)
- Screenshots of every action
- Security audit report
- Code simplification report
- SDLC cycle report

## 🎯 Windows 11 Specific

### Verified On
- Windows 11
- PowerShell 7
- Chrome browser
- Selenium WebDriver

### Requirements
- Python 3.8+
- Chrome browser installed
- Rust toolchain (for building)
- Node.js (for frontend, optional)

## ✅ Success Indicators

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

## 🔍 Troubleshooting

### Browser Won't Start
- Install Chrome
- Check ChromeDriver version
- Verify Selenium installation

### API Server Won't Start
- Check if port 3006 is available
- Verify binary exists
- Check database initialization

### Frontend Won't Start
- Run `npm install` in frontend directory
- Check Node.js version
- Verify dependencies

## 📝 Next Steps

1. **Run First Cycle**: `.\sdlc\start_ua_session.ps1`
2. **Review Reports**: Check all JSON and log files
3. **Make Improvements**: Fix identified issues
4. **Run Next Cycle**: Verify improvements
5. **Iterate**: Continue until satisfied

---

**Ready to start iterative SDLC cycles!**

