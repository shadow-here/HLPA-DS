# Build and start the whole HLPA-DS stack.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path (Join-Path $root ".env"))) { Write-Host "No .env found - running setup first..." -ForegroundColor Yellow; & (Join-Path $PSScriptRoot "setup.ps1") }
docker compose up -d --build
Write-Host ""
Write-Host "HLPA-DS starting. Open the dashboard at:  http://localhost:8080" -ForegroundColor Green
Write-Host "Check status with:  docker compose ps"
