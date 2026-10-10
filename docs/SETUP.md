# Setup & Operations Guide

## 1. Prerequisites

- **Docker Desktop** (Windows/macOS) or **Docker Engine + Compose v2** (Linux),
  running. On Windows, the WSL 2 backend is recommended.
- About **8 GB RAM** free and **~40 GB disk** for images and data.
- A web browser (current Chrome, Edge or Firefox).

Check Docker is ready:

```powershell
docker version
docker compose version
```

## 2. Configure

From the project root (the folder with `docker-compose.yml`):

```powershell
.\scripts\setup.ps1          # Windows
# ./scripts/setup.sh         # Linux/macOS
```

This copies `.env.example` to `.env` and fills in random secrets
(`JWT_SECRET`, `REDACTION_KEY`, `CONTROLLER_TOKEN`) and generated passwords for
the `admin`, `analyst` and `viewer` accounts. **The accounts are printed to the
console and saved in `.env`** — note them down.

To configure by hand instead, copy `.env.example` to `.env` and edit it. Every
tunable (host ports, lab CIDR, retention) is documented inline in that file.

> The `.env` file holds secrets. It is listed in `.gitignore` — never commit it.

## 3. Build & start

```powershell
docker compose up -d --build
```

The first build compiles the frontend and installs the honeypots, so it takes a
few minutes. Afterwards:

```powershell
docker compose ps            # all services should be "running"/"healthy"
```

Open **http://localhost:8080** and sign in as `admin`.

## 4. Load demo data (optional)

```powershell
.\scripts\replay-samples.ps1         # or: docker compose run --rm replay --fresh-times
```

This replays **synthetic** sensor logs (fabricated records — no network traffic)
so the dashboard fills with events and alerts for rules `DET-01`–`DET-08`. Use it
for a demo or to verify the pipeline end-to-end.

## 5. Enable the live decoys

Decoys start **disabled**. To capture real hand-driven lab interactions:

1. Open **Decoys** in the dashboard (as `admin`).
2. Click **Enable…** on a decoy.
3. Tick every item on the **isolation checklist** (authorized interface, inbound
   restricted, egress blocked, no real secrets, no production reach).
4. **Confirm & enable.** The controller starts the container; health goes from
   *pending* to *healthy* after the collector's next check.

The published decoy ports (all on `127.0.0.1` by default) are:

| Decoy | Host port | Service |
|---|---|---|
| Cowrie | `127.0.0.1:2222` / `:2223` | SSH / Telnet |
| OpenCanary | `127.0.0.1:2121` / `:13306` / `:16379` | FTP / MySQL / Redis |
| HTTP decoy | `127.0.0.1:8888` | Web admin console |

Interacting with these from your own machine (inside the authorized lab) produces
events and, past the thresholds, alerts.

## 6. Stop, reset, recover

```powershell
.\scripts\stop.ps1                 # stop, keep all data
.\scripts\stop.ps1 -Wipe           # stop AND delete data volumes (fresh start)
docker compose restart collector   # restart one service
.\scripts\emergency-stop.ps1       # kill switch: stop all decoys immediately
```

Stored events survive a normal restart (data lives in Docker volumes
`mongo_data`, `cowrie_logs`, …). The collector tracks a read cursor per log, so
restarting it does not re-ingest everything.

## 7. Change passwords / add users

Sign in as `admin` → **Administration → Users**. You can add analysts/viewers,
change roles, reset passwords and disable accounts. At least one active admin is
always required.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` fails pulling images | Check internet access; Docker needs to pull `mongo`, `node`, `nginx`, `python` base images on first build. |
| Dashboard loads but "collector" dot is red/stale | `docker compose logs collector` — usually it is still starting or waiting for MongoDB. |
| "controller not reachable" on the Decoys page | `docker compose logs controller`. Enable/disable needs it; the rest works alert-first without it. |
| Health shows a decoy "unhealthy" after enabling | Give it ~15 s for the first probe, then `docker compose logs <decoy>`. |
| Port already in use | Change the `*_PORT` values in `.env` and `docker compose up -d` again. |
| Want a clean slate | `.\scripts\stop.ps1 -Wipe` then `docker compose up -d --build`. |
| "no space left on device" | Free Docker space: `docker system prune` (removes unused images/volumes — be careful). |

## 9. Running without Docker (developer mode)

Each component runs standalone for development:

- **MongoDB** on `localhost:27017` (install locally or run `docker run -p 27017:27017 mongo:7`).
- **API:** `cd api && npm install && MONGO_URL=mongodb://localhost:27017 JWT_SECRET=dev ADMIN_PASSWORD=devpass123 npm start`
- **Collector:** `cd collector && pip install -r requirements-dev.txt && MONGO_URL=mongodb://localhost:27017 SOURCES="cowrie=...,opencanary=...,http_decoy=..." python -m hlpa_collector.main`
- **Frontend:** `cd frontend && npm install && npm run dev` (proxies `/api` to `localhost:4000`).

See `docs/TESTING.md` to run the test suites.
