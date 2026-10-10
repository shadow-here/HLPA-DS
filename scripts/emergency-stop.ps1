# EMERGENCY: immediately stop every decoy container (the kill switch).
# The rest of the platform (dashboard, API, database) keeps running so you can
# still review what happened.
$ErrorActionPreference = "Continue"
Write-Host "Stopping all HLPA-DS decoy containers..." -ForegroundColor Red
docker stop hlpa-cowrie hlpa-opencanary hlpa-http-decoy
Write-Host "Decoys stopped. Review the dashboard, then re-enable from the Decoys page when safe." -ForegroundColor Yellow
