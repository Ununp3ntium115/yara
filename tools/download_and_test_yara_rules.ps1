# Download and Test YARA Rules
# Downloads the latest YARA rules zip and tests them on this PC

param(
    [string]$OutputDir = "test_rules",
    [string]$TestDir = "$env:TEMP\yara_test_files",
    [switch]$UseCryptex = $false
)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot | Split-Path -Parent

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "YARA Rules Download & Test" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Create output directory
$outputPath = Join-Path $rootDir $OutputDir
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

# Known YARA rules repositories
$repositories = @(
    @{
        Name = "YARA-Rules (Official)"
        Url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        Description = "Official YARA rules repository"
    },
    @{
        Name = "Neo23x0 Signatures"
        Url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
        Description = "Neo23x0 signature base"
    },
    @{
        Name = "InQuest YARA Rules"
        Url = "https://github.com/InQuest/yara-rules/archive/refs/heads/master.zip"
        Description = "InQuest YARA rules collection"
    },
    @{
        Name = "ReversingLabs YARA Rules"
        Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"
        Description = "ReversingLabs YARA rules"
    }
)

Write-Host "📦 Available YARA Rules Repositories:" -ForegroundColor Cyan
Write-Host "-" * 60
for ($i = 0; $i -lt $repositories.Count; $i++) {
    Write-Host "$($i + 1). $($repositories[$i].Name)" -ForegroundColor White
    Write-Host "   $($repositories[$i].Description)" -ForegroundColor Gray
    Write-Host "   $($repositories[$i].Url)" -ForegroundColor DarkGray
    Write-Host ""
}

# Try to download from the first repository (YARA-Rules official)
$selectedRepo = $repositories[0]
$zipFile = Join-Path $outputPath "yara-rules.zip"
$extractPath = Join-Path $outputPath "yara-rules-extracted"

Write-Host "📥 Downloading from: $($selectedRepo.Name)" -ForegroundColor Yellow
Write-Host "   URL: $($selectedRepo.Url)" -ForegroundColor Gray

try {
    # Download the zip file
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $selectedRepo.Url -OutFile $zipFile -UseBasicParsing
    Write-Host "✅ Download complete: $zipFile" -ForegroundColor Green
    
    # Extract the zip file
    Write-Host "`n📂 Extracting zip file..." -ForegroundColor Yellow
    if (Test-Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }
    Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
    Write-Host "✅ Extraction complete: $extractPath" -ForegroundColor Green
    
    # Find all .yar files
    $yarFiles = Get-ChildItem -Path $extractPath -Filter "*.yar" -Recurse
    Write-Host "`n📊 Found $($yarFiles.Count) YARA rule files" -ForegroundColor Cyan
    
    if ($yarFiles.Count -eq 0) {
        Write-Host "⚠️  No .yar files found in extracted archive" -ForegroundColor Yellow
        Write-Host "   Checking for .yara files..." -ForegroundColor Yellow
        $yaraFiles = Get-ChildItem -Path $extractPath -Filter "*.yara" -Recurse
        if ($yaraFiles.Count -gt 0) {
            Write-Host "   Found $($yaraFiles.Count) .yara files" -ForegroundColor Green
            $yarFiles = $yaraFiles
        }
    }
    
    # Create a combined rules file for testing
    $combinedRulesFile = Join-Path $outputPath "combined_rules.yar"
    Write-Host "`n🔗 Creating combined rules file..." -ForegroundColor Yellow
    
    $ruleCount = 0
    $combinedContent = New-Object System.Text.StringBuilder
    
    foreach ($file in $yarFiles | Select-Object -First 100) { # Limit to first 100 for testing
        try {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                [void]$combinedContent.AppendLine("// From: $($file.FullName)")
                [void]$combinedContent.AppendLine($content)
                [void]$combinedContent.AppendLine("")
                $ruleCount++
            }
        } catch {
            # Skip files that can't be read
        }
    }
    
    $combinedContent.ToString() | Out-File -FilePath $combinedRulesFile -Encoding UTF8
    Write-Host "✅ Combined rules file created: $combinedRulesFile" -ForegroundColor Green
    Write-Host "   Rules included: $ruleCount" -ForegroundColor Cyan
    
    # Test the rules
    Write-Host "`n🧪 Testing YARA rules..." -ForegroundColor Yellow
    
    # Check if Python scanner is available
    $scannerScript = Join-Path $rootDir "yara_scanner.py"
    if (Test-Path $scannerScript) {
        Write-Host "   Using Python scanner: $scannerScript" -ForegroundColor Cyan
        
        # Create test directory with some files
        if (-not (Test-Path $TestDir)) {
            New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
        }
        
        # Create a test file
        $testFile = Join-Path $TestDir "test_file.txt"
        "This is a test file for YARA scanning" | Out-File -FilePath $testFile -Encoding UTF8
        
        # Run the scanner
        $scannerArgs = @(
            "-r", $combinedRulesFile,
            "-d", $TestDir,
            "-o", (Join-Path $outputPath "scan_results.json")
        )
        if ($UseCryptex) {
            $scannerArgs += "--cryptex"
        }
        
        Write-Host "   Running scanner..." -ForegroundColor Cyan
        Write-Host "   Command: python $scannerScript $($scannerArgs -join ' ')" -ForegroundColor Gray
        python $scannerScript $scannerArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Scanner test complete!" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Scanner test had issues (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️  Python scanner not found: $scannerScript" -ForegroundColor Yellow
    }
    
    # Summary
    Write-Host "`n📊 Summary:" -ForegroundColor Cyan
    Write-Host "-" * 60
    Write-Host "Repository: $($selectedRepo.Name)" -ForegroundColor White
    Write-Host "Downloaded: $zipFile" -ForegroundColor White
    Write-Host "Extracted: $extractPath" -ForegroundColor White
    Write-Host "Rule files found: $($yarFiles.Count)" -ForegroundColor White
    Write-Host "Combined rules: $combinedRulesFile" -ForegroundColor White
    Write-Host "Rules in combined file: $ruleCount" -ForegroundColor White
    Write-Host ""
    Write-Host "✅ YARA rules downloaded and ready for testing!" -ForegroundColor Green
    Write-Host "`n💡 Next steps:" -ForegroundColor Yellow
    Write-Host "   • Test with: python yara_scanner.py $combinedRulesFile <target_dir>" -ForegroundColor White
    Write-Host "   • Use Cryptex: python yara_scanner.py $combinedRulesFile <target_dir> --use-cryptex" -ForegroundColor White
    Write-Host "   • View results: Get-Content $outputPath\scan_results.json" -ForegroundColor White
    
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    Write-Host "   Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}

