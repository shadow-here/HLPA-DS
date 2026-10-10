# Run the automated test suites (collector + API) inside containers.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "== Collector / detection tests ==" -ForegroundColor Cyan
docker compose run --rm --entrypoint "python" collector -m pytest tests/ -q
Write-Host "== API tests ==" -ForegroundColor Cyan
docker compose run --rm --entrypoint "sh" api -c "MONGO_URL=mongodb://mongo:27017 npm test"
