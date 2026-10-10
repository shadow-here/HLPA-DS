#!/usr/bin/env bash
# HLPA-DS setup helper (Linux / macOS). Creates .env with generated secrets.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
env_file="$root/.env"
[ -f "$env_file" ] && { echo ".env already exists - not overwriting."; exit 0; }
secret() { head -c "${1:-24}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sed \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$(secret 32)|" \
  -e "s|^REDACTION_KEY=.*|REDACTION_KEY=$(secret 24)|" \
  -e "s|^CONTROLLER_TOKEN=.*|CONTROLLER_TOKEN=$(secret 24)|" \
  -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=Admin-$(secret 6)!|" \
  -e "s|^ANALYST_PASSWORD=.*|ANALYST_PASSWORD=Analyst-$(secret 6)!|" \
  -e "s|^VIEWER_PASSWORD=.*|VIEWER_PASSWORD=Viewer-$(secret 6)!|" \
  "$root/.env.example" > "$env_file"
echo "Created .env with generated secrets. Your accounts:"
grep -E '^(ADMIN|ANALYST|VIEWER)_(USERNAME|PASSWORD)=' "$env_file" | sed 's/^/  /'
echo; echo "Next:  docker compose up -d --build"
