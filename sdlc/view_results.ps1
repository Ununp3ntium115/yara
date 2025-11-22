# YARA Cryptex - View SDLC Results
# Quick viewer for SDLC cycle results

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "YARA Cryptex - SDLC Results Viewer" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

python sdlc/view_results.py

Write-Host ""
Write-Host "💡 For detailed reports, check:" -ForegroundColor Yellow
Write-Host "   - sdlc/security_audit_*.json" -ForegroundColor White
Write-Host "   - sdlc/code_simplification_*.json" -ForegroundColor White
Write-Host "   - sdlc/cycles/cycle_*.json" -ForegroundColor White
Write-Host "   - ua_logs/interactions_*.json" -ForegroundColor White
Write-Host "   - ua_logs/screenshots/" -ForegroundColor White
Write-Host ""

