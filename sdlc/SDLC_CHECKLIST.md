# SDLC Cycle Checklist

## ✅ Pre-Cycle Checklist

### Setup
- [ ] Dependencies installed (`.\sdlc\setup_sdlc.ps1`)
- [ ] Setup verified (`python sdlc\verify_setup.py`)
- [ ] Quick test passed (`python sdlc\quick_test.py`)

### Prerequisites
- [ ] Python 3.8+ installed
- [ ] Chrome browser installed
- [ ] PowerShell 7+ available
- [ ] Rust toolchain (if building)
- [ ] Node.js (if frontend needed)

---

## 🔄 SDLC Cycle Checklist

### Step 1: Security Audit
- [ ] Security audit run
- [ ] Report generated: `sdlc/security_audit_*.json`
- [ ] Vulnerabilities reviewed
- [ ] Critical issues documented

### Step 2: Code Simplification
- [ ] Code analysis run
- [ ] Report generated: `sdlc/code_simplification_*.json`
- [ ] Complexity issues reviewed
- [ ] Simplification opportunities identified

### Step 3: Build
- [ ] System builds successfully
- [ ] Binaries created
- [ ] No build errors
- [ ] Build warnings reviewed

### Step 4: Start Services
- [ ] API server started
- [ ] Frontend started (if available)
- [ ] Services responding
- [ ] Ports available

### Step 5: UA Testing
- [ ] Browser opened
- [ ] Pages navigated
- [ ] Interactions tested
- [ ] Screenshots captured
- [ ] Interactions logged

### Step 6: Review
- [ ] Security findings reviewed
- [ ] Code complexity reviewed
- [ ] UI interactions reviewed
- [ ] Screenshots reviewed
- [ ] Issues documented

### Step 7: Improve
- [ ] Security issues fixed
- [ ] Code simplified
- [ ] UI issues fixed
- [ ] Documentation updated

### Step 8: Repeat
- [ ] Next cycle planned
- [ ] Improvements verified
- [ ] Iteration continued

---

## 📊 Results Checklist

### Reports Generated
- [ ] Security audit report
- [ ] Code simplification report
- [ ] SDLC cycle report
- [ ] UA interaction log
- [ ] Session report

### Screenshots
- [ ] Before-action screenshots
- [ ] After-action screenshots
- [ ] Error screenshots
- [ ] Final state screenshot

### Logs
- [ ] Session log
- [ ] Interaction log
- [ ] Console logs
- [ ] Error logs

---

## ✅ Post-Cycle Checklist

### Review
- [ ] All reports reviewed
- [ ] Issues identified
- [ ] Improvements planned
- [ ] Results documented

### Cleanup (Optional)
- [ ] Old logs cleaned (`.\sdlc\cleanup_old_logs.ps1`)
- [ ] Results exported (`.\sdlc\export_results.ps1`)
- [ ] Cycles compared (`.\sdlc\compare_cycles.ps1`)

### Next Steps
- [ ] Improvements implemented
- [ ] Next cycle scheduled
- [ ] Documentation updated

---

## 🎯 Success Criteria

### Cycle Successful If:
- ✅ All steps completed
- ✅ No critical security issues
- ✅ Code complexity acceptable
- ✅ All UI interactions logged
- ✅ Screenshots captured
- ✅ Reports generated

### Cycle Needs Improvement If:
- ⚠️ Steps failed
- ⚠️ Critical security issues found
- ⚠️ High code complexity
- ⚠️ Interactions not logged
- ⚠️ Screenshots missing
- ⚠️ Reports incomplete

---

## 📝 Notes

### Cycle Number: ___
### Date: ___
### Duration: ___
### Issues Found: ___
### Improvements Made: ___

---

**Use this checklist for each SDLC cycle to ensure completeness!**

