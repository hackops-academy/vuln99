# setup.ps1 — one-command install + run for vuln99 on Windows.
#
#   .\setup.ps1              install deps (if needed) and start the app
#   .\setup.ps1 -Install     install/refresh deps only, don't start
#   .\setup.ps1 -Test        install dev deps and run the smoke test suite
#
# Safe by default: the app binds to 127.0.0.1 unless you set $env:VULN99_HOST
# yourself before running this script. See vuln99\config.py.

param(
    [switch]$Install,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$VenvDir = "venv"

if (-not (Test-Path $VenvDir)) {
    Write-Host "==> Creating virtual environment in .\$VenvDir"
    python -m venv $VenvDir
}

$activate = Join-Path $VenvDir "Scripts\Activate.ps1"
. $activate

if ($Test) {
    Write-Host "==> Installing dev requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements-dev.txt
    Write-Host "==> Running smoke tests"
    pytest -q
} elseif ($Install) {
    Write-Host "==> Installing requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    Write-Host "==> Done. Activate with: $activate"
} else {
    Write-Host "==> Installing requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    Write-Host "==> Starting vuln99 (Ctrl+C to stop)"
    Write-Host "    Host: $(if ($env:VULN99_HOST) { $env:VULN99_HOST } else { '127.0.0.1' })   Port: $(if ($env:VULN99_PORT) { $env:VULN99_PORT } else { '5099' })"
    python run.py
}
