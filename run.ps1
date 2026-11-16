# HybridSec launcher for Windows PowerShell.
# Creates a virtual environment on first start, installs (or repairs) the dependencies on every start,
# then starts the server. If PowerShell refuses to run scripts ("running scripts is disabled on this
# system"), start run.cmd instead: it runs this file with -ExecutionPolicy Bypass for that one process.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Invoke-Checked([string]$What, [scriptblock]$Command) {
    # Windows PowerShell 5.1 does not stop when a native program fails, so check the exit code ourselves.
    & $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$What failed (exit code $LASTEXITCODE). Fix the error above and run the script again." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

function Get-EnvFileValue([string]$Key) {
    # KEY=value from .env (the last occurrence wins; quotes and inline comments are removed).
    if (-not (Test-Path ".env")) { return $null }
    $line = Get-Content ".env" | Where-Object { $_ -match "^\s*$Key\s*=" } | Select-Object -Last 1
    if (-not $line) { return $null }
    $value = ($line -split "=", 2)[1]
    $value = ($value -split "\s+#", 2)[0].Trim().Trim('"').Trim("'")
    if ($value -eq "") { return $null }
    return $value
}

# 1. Python 3.10 or newer must be on PATH.
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python was not found on PATH. Install Python 3.10 or newer from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "and tick 'Add python.exe to PATH' in the installer, then run this script again." -ForegroundColor Red
    exit 1
}
& python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "HybridSec needs Python 3.10 or newer. Install a current Python from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "(if the message above came from the Microsoft Store, Python is not really installed yet)." -ForegroundColor Red
    exit 1
}

# 2. Virtual environment: created once, and created again if an earlier attempt was interrupted (no
#    interpreter or no pip inside); re-running venv on the folder keeps the packages already installed.
$python = ".\.venv\Scripts\python.exe"
$needVenv = -not (Test-Path $python)
if (-not $needVenv) {
    # A .venv without pip (interrupted creation) is repaired by running venv again, which keeps installed packages.
    & $python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('pip') is None)"
    $needVenv = ($LASTEXITCODE -ne 0)
}
if ($needVenv) {
    Write-Host "Creating virtual environment..."
    Invoke-Checked "Creating the virtual environment" { python -m venv .venv }
}

# 3. Dependencies. pip finishes in about a second when everything is already installed, so running it on
#    every start costs little and repairs an install that was interrupted or ran without a network.
Write-Host "Checking dependencies (the first install can take a minute)..."
Invoke-Checked "Installing the dependencies (is the machine online?)" {
    & $python -m pip install --quiet --disable-pip-version-check -r requirements.txt
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example (edit it, or use the dashboard's Settings page, to add an API key or scope restrictions)."
}

# 4. Bind address and port: the shell environment wins, then .env, then the safe defaults.
$bind = $env:HYBRIDSEC_HOST
if (-not $bind) { $bind = Get-EnvFileValue "HYBRIDSEC_HOST" }
if (-not $bind) { $bind = "127.0.0.1" }
$port = $env:HYBRIDSEC_PORT
if (-not $port) { $port = Get-EnvFileValue "HYBRIDSEC_PORT" }
if (-not $port) { $port = "8000" }

Write-Host ""
Write-Host "HybridSec dashboard:  http://${bind}:${port}/"
Write-Host "API docs (Swagger):   http://${bind}:${port}/docs"
Write-Host "Stop the server with Ctrl+C."
Write-Host ""
& $python -m uvicorn app.main:app --host $bind --port $port
# powershell -File exits with 0 when a script simply ends, so pass uvicorn's exit code on: a failed start
# (for example a port already in use) then makes run.cmd pause so the error stays readable.
exit $LASTEXITCODE
