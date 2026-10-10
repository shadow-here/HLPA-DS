# Replay the synthetic sample logs so the dashboard fills with demo data.
# Fabricated log records only - no network traffic is generated.
param([double]$Speed = 20)
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
docker compose run --rm replay --fresh-times --speed $Speed
Write-Host "Replay complete. Open http://localhost:8080 and watch for new alerts." -ForegroundColor Green
