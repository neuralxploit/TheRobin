# TheRobin — Windows Environment Setup
# Run once: powershell -ExecutionPolicy Bypass -File setup.ps1
# Then use: .\run.ps1  OR  .venv\Scripts\activate && python main.py

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$VenvDir = ".venv"

Write-Host ""
Write-Host "  +----------------------------------------------------+"
Write-Host "  |      TheRobin - Setup (Windows)                     |"
Write-Host "  +----------------------------------------------------+"
Write-Host ""

# Check Python
$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    $Python = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $Python) {
    Write-Host "  [ERROR] Python not found. Install Python 3.10+ from https://python.org" -ForegroundColor Red
    exit 1
}
$PythonExe = $Python.Source
$PythonVersion = & $PythonExe --version 2>&1
Write-Host "  [OK] $PythonVersion found"

# Check Ollama
try {
    $null = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 -ErrorAction Stop
    Write-Host "  [OK] Ollama is running"
} catch {
    Write-Host "  [WARN] Ollama not responding at localhost:11434" -ForegroundColor Yellow
    Write-Host "         Start it with: ollama serve"
}

# Check LM Studio
try {
    $null = Invoke-RestMethod -Uri "http://localhost:1234/v1/models" -TimeoutSec 3 -ErrorAction Stop
    Write-Host "  [OK] LM Studio is running"
} catch {
    Write-Host "  [INFO] LM Studio not detected at localhost:1234 (optional)" -ForegroundColor Gray
}

# Create venv
Write-Host ""
Write-Host "  Creating virtual environment..."
& $PythonExe -m venv $VenvDir
Write-Host "  [OK] venv created at .\$VenvDir"

# Activate and install
$VenvPython = Join-Path $RepoRoot "$VenvDir\Scripts\python.exe"
$VenvPip = Join-Path $RepoRoot "$VenvDir\Scripts\pip.exe"

Write-Host ""
Write-Host "  Installing dependencies..."
& $VenvPip install --upgrade pip --quiet 2>$null
& $VenvPip install -r requirements.txt --quiet 2>$null
Write-Host "  [OK] Dependencies installed"

# Check for Chrome
Write-Host ""
$ChromePaths = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$ChromeFound = $false
foreach ($p in $ChromePaths) {
    if (Test-Path $p) {
        Write-Host "  [OK] Chrome found at $p"
        $ChromeFound = $true
        break
    }
}
if (-not $ChromeFound) {
    Write-Host "  [WARN] Chrome not found - browser screenshot features will be disabled" -ForegroundColor Yellow
    Write-Host "         Install Google Chrome from https://www.google.com/chrome/"
}

# Create run script
$RunScript = @"
@echo off
cd /d "%~dp0"
call .venv\Scripts\activate
python main.py %*
"@
Set-Content -Path (Join-Path $RepoRoot "run.bat") -Value $RunScript -Encoding ASCII

# Also create a PowerShell run script
$RunPs1 = @'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot
& ".venv\Scripts\activate.ps1"
python main.py @args
'@
Set-Content -Path (Join-Path $RepoRoot "run.ps1") -Value $RunPs1 -Encoding UTF8

# Generate .mcp.json for Claude Code
Write-Host ""
Write-Host "  Generating .mcp.json for Claude Code..."
$PythonPath = ($VenvPython -replace '\\', '/')
$RepoRootFwd = ($RepoRoot -replace '\\', '/')
$Template = Get-Content (Join-Path $RepoRoot ".mcp.json.template") -Raw
$McpJson = $Template -replace '__PYTHON_PATH__', $PythonPath -replace '__REPO_ROOT__', $RepoRootFwd
Set-Content -Path (Join-Path $RepoRoot ".mcp.json") -Value $McpJson -Encoding UTF8
Write-Host "  [OK] .mcp.json generated"

Write-Host ""
Write-Host "  +----------------------------------------------------+"
Write-Host "  |  Setup complete!                                     |"
Write-Host "  |                                                      |"
Write-Host "  |  Start console:  .\run.bat                           |"
Write-Host "  |  With target:    .\run.bat -t http://target.com      |"
Write-Host "  |  With LM Studio: .\run.bat -m lmstudio:model-name   |"
Write-Host "  +----------------------------------------------------+"
Write-Host ""
