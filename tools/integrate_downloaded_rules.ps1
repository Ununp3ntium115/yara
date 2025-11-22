# Integrate Downloaded YARA Rules with Feed Scanner
# Shows how to use downloaded rules with the complete system

param(
    [string]$RulesDir = "test_rules\yara-rules-extracted",
    [switch]$StartAPI = $false
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Rules Integration" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

$rulesPath = Join-Path $rootDir $RulesDir
if (-not (Test-Path $rulesPath)) {
    Write-Host "❌ Rules directory not found: $rulesPath" -ForegroundColor Red
    exit 1
}

# Count rules
$yarFiles = Get-ChildItem -Path $rulesPath -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
if ($yarFiles.Count -eq 0) {
    $yaraFiles = Get-ChildItem -Path $rulesPath -Filter "*.yara" -Recurse -ErrorAction SilentlyContinue
    if ($yaraFiles.Count -gt 0) {
        $yarFiles = $yaraFiles
    }
}

Write-Host "📊 Found $($yarFiles.Count) YARA rule files" -ForegroundColor Cyan

# Show integration options
Write-Host "`n🔗 Integration Options:" -ForegroundColor Yellow
Write-Host "-" * 60

Write-Host "`n1. Use with Python Scanner:" -ForegroundColor Cyan
Write-Host "   python yara_scanner.py -r $RulesDir\<category>\<rule>.yar -d <target>" -ForegroundColor White

Write-Host "`n2. Use with Cryptex API:" -ForegroundColor Cyan
if ($StartAPI) {
    $apiBinary = Join-Path $rootDir "rust\cryptex-api\target\release\cryptex-api.exe"
    if (Test-Path $apiBinary) {
        Write-Host "   Starting API server..." -ForegroundColor Yellow
        Start-Process -FilePath $apiBinary -ArgumentList "--port", "3006" -WindowStyle Minimized
        Start-Sleep -Seconds 3
        Write-Host "   ✅ API server started on port 3006" -ForegroundColor Green
        Write-Host "   Test: Invoke-WebRequest http://localhost:3006/api/v2/yara/cryptex/stats" -ForegroundColor White
    } else {
        Write-Host "   ⚠️  API binary not found. Build with: cd rust && cargo build --release" -ForegroundColor Yellow
    }
} else {
    Write-Host "   Start API: .\tools\integrate_downloaded_rules.ps1 -StartAPI" -ForegroundColor White
    Write-Host "   Then use feed scanner to discover more rules" -ForegroundColor White
}

Write-Host "`n3. Use with Feed Scanner:" -ForegroundColor Cyan
Write-Host "   The feed scanner can discover additional rules from:" -ForegroundColor White
Write-Host "   • GitHub repositories" -ForegroundColor Gray
Write-Host "   • RSS/Atom feeds" -ForegroundColor Gray
Write-Host "   • Direct URLs" -ForegroundColor Gray
Write-Host "   Run: cd rust\yara-feed-scanner && cargo run -- scan" -ForegroundColor White

Write-Host "`n4. Use with Node-RED:" -ForegroundColor Cyan
Write-Host "   Import rules into Node-RED flows" -ForegroundColor White
Write-Host "   Use cryptex-lookup and yara-feed-scanner nodes" -ForegroundColor White

Write-Host "`n5. Use with Svelte Frontend:" -ForegroundColor Cyan
Write-Host "   Browse rules via: http://localhost:5173/tools/yara/cryptex" -ForegroundColor White
Write-Host "   Scan feeds via: http://localhost:5173/tools/yara/feed" -ForegroundColor White

# Create a rules index
Write-Host "`n📋 Creating rules index..." -ForegroundColor Yellow
$indexFile = Join-Path $rootDir "test_rules\rules_index.json"

$index = @{
    total_rules = $yarFiles.Count
    download_date = (Get-Date -Format "yyyy-MM-dd")
    source = "YARA-Rules (Official) - GitHub"
    categories = @{}
}

foreach ($file in $yarFiles) {
    $category = $file.Directory.Name
    if (-not $index.categories.ContainsKey($category)) {
        $index.categories[$category] = @()
    }
    $index.categories[$category] += @{
        name = $file.Name
        path = $file.FullName.Replace($rootDir, "").Replace("\", "/")
        size = $file.Length
    }
}

$index | ConvertTo-Json -Depth 10 | Out-File -FilePath $indexFile -Encoding UTF8
Write-Host "✅ Rules index created: $indexFile" -ForegroundColor Green

# Summary
Write-Host "`n📊 Integration Summary:" -ForegroundColor Cyan
Write-Host "-" * 60
Write-Host "Total Rules: $($yarFiles.Count)" -ForegroundColor White
Write-Host "Categories: $($index.categories.Count)" -ForegroundColor White
Write-Host "Index File: $indexFile" -ForegroundColor White
Write-Host "`n✅ Rules ready for integration!" -ForegroundColor Green

Write-Host "`n💡 Quick Start:" -ForegroundColor Yellow
Write-Host "   # Test a rule:" -ForegroundColor White
Write-Host "   python yara_scanner.py -r test_rules\yara-rules-extracted\<category>\<rule>.yar -d C:\Windows\System32" -ForegroundColor Gray
Write-Host "`n   # View index:" -ForegroundColor White
Write-Host "   Get-Content test_rules\rules_index.json | ConvertFrom-Json" -ForegroundColor Gray

