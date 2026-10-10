# Stop the stack (keeps data). Add -Wipe to also delete all stored data volumes.
param([switch]$Wipe)
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if ($Wipe) { docker compose down -v; Write-Host "Stack stopped and data volumes removed." -ForegroundColor Yellow }
else { docker compose down; Write-Host "Stack stopped. Data preserved. Use -Wipe to remove data." -ForegroundColor Green }
