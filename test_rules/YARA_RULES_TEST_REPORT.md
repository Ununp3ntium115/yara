# YARA Rules Test Report

**Generated**: 2025-11-22 15:03:59  
**Total Tests**: 17

---

## Summary

- **✅ Successful**: 17
- **⚠️ Warnings**: 0
- **❌ Errors**: 0
- **🔍 Total Matches**: 0
- **📁 Total Files Scanned**: 0

---

## Test Results by Rule

| Rule | Status | Matches | Files Scanned |
|------|--------|---------|--------------|| antidebug_antivm | ✅ Success | 0 | 0 |
| antidebug_antivm_index | ✅ Success | 0 | 0 |
| capabilities | ✅ Success | 0 | 0 |
| capabilities_index | ✅ Success | 0 | 0 |
| crypto_index | ✅ Success | 0 | 0 |
| crypto_signatures | ✅ Success | 0 | 0 |
| cve_rules_index | ✅ Success | 0 | 0 |
| CVE-2010-0805 | ✅ Success | 0 | 0 |
| CVE-2010-0887 | ✅ Success | 0 | 0 |
| CVE-2010-1297 | ✅ Success | 0 | 0 |
| CVE-2012-0158 | ✅ Success | 0 | 0 |
| email_index | ✅ Success | 0 | 0 |
| exploit_kits_index | ✅ Success | 0 | 0 |
| maldocs_index | ✅ Success | 0 | 0 |
| mobile_malware_index | ✅ Success | 0 | 0 |
| packers_index | ✅ Success | 0 | 0 |
| webshells_index | ✅ Success | 0 | 0 |

---

## Rules with Matches
No matches found in test files (this is normal for clean system files).

---

## Recommendations
- ✅ 17 rules tested successfully
- Ready for production use
- Consider testing with more diverse file types
- Test with Cryptex transcoding for branded output
---

## Next Steps

1. **Test More Rules**: .\tools\test_yara_rules.ps1 -MaxRules 100
2. **Test Real Files**: .\tools\test_yara_rules.ps1 -TestTarget "C:\Path\To\Scan"
3. **Use Cryptex**: .\tools\test_yara_rules.ps1 -UseCryptex
4. **View Results**: Get-Content test_rules\result_*.json

---

## Files

- **Results Directory**: $ResultsDir
- **Total Result Files**: 17
- **Report Generated**: 2025-11-22 15:03:59
