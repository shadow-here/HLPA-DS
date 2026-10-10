# HLPA-DS setup helper (Windows PowerShell).
# Creates a .env from .env.example with freshly generated secrets.
# Run from the project root:  .\scripts\setup.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $root ".env"
$examplePath = Join-Path $root ".env.example"

if (Test-Path $envPath) {
  Write-Host ".env already exists at $envPath - not overwriting." -ForegroundColor Yellow
  Write-Host "Delete it first if you want to regenerate secrets."
  exit 0
}

function New-Secret([int]$bytes = 24) {
  $b = New-Object 'System.Byte[]' $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return [System.BitConverter]::ToString($b).Replace("-", "").ToLower()
}

$content = Get-Content $examplePath -Raw
$content = $content -replace "JWT_SECRET=.*", "JWT_SECRET=$(New-Secret 32)"
$content = $content -replace "REDACTION_KEY=.*", "REDACTION_KEY=$(New-Secret 24)"
$content = $content -replace "CONTROLLER_TOKEN=.*", "CONTROLLER_TOKEN=$(New-Secret 24)"
$content = $content -replace "ADMIN_PASSWORD=.*", "ADMIN_PASSWORD=Admin-$(New-Secret 6)!"
$content = $content -replace "ANALYST_PASSWORD=.*", "ANALYST_PASSWORD=Analyst-$(New-Secret 6)!"
$content = $content -replace "VIEWER_PASSWORD=.*", "VIEWER_PASSWORD=Viewer-$(New-Secret 6)!"
Set-Content -Path $envPath -Value $content -NoNewline

Write-Host "Created .env with generated secrets." -ForegroundColor Green
Write-Host "Your login accounts (also saved in .env):" -ForegroundColor Cyan
Select-String -Path $envPath -Pattern "^(ADMIN|ANALYST|VIEWER)_(USERNAME|PASSWORD)=" | ForEach-Object { "  " + $_.Line }
Write-Host ""
Write-Host "Next:  docker compose up -d --build" -ForegroundColor Green
