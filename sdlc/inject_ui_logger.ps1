# Inject UI Logger into Svelte Frontend
# Adds client-side interaction logging to all pages

$frontendPath = "pyro-platform\frontend-svelte\src"
$loggerFile = "sdlc\ui_interaction_logger.js"

if (-not (Test-Path $frontendPath)) {
    Write-Host "Frontend path not found: $frontendPath" -ForegroundColor Red
    exit 1
}

# Copy logger to frontend static directory
$staticDir = "$frontendPath\lib"
New-Item -ItemType Directory -Force -Path $staticDir | Out-Null

Copy-Item $loggerFile "$staticDir\ui_logger.js" -Force

Write-Host "✅ UI logger copied to frontend" -ForegroundColor Green

# Check if app.html exists to inject script
$appHtml = "pyro-platform\frontend-svelte\src\app.html"
if (Test-Path $appHtml) {
    $content = Get-Content $appHtml -Raw
    
    if ($content -notmatch "ui_logger.js") {
        # Inject before closing body tag
        $content = $content -replace '</body>', "  <script src='/lib/ui_logger.js'></script>`n</body>"
        Set-Content $appHtml $content
        Write-Host "✅ UI logger injected into app.html" -ForegroundColor Green
    } else {
        Write-Host "ℹ️  UI logger already in app.html" -ForegroundColor Cyan
    }
} else {
    Write-Host "⚠️  app.html not found, manual injection may be needed" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "💡 UI logger will now log all interactions when frontend runs" -ForegroundColor Cyan

