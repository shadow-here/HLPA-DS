# Command How-To — every command, what it does

A practical reference for running HLPA-DS. Primary instructions are **Windows
PowerShell** (your setup); Linux/macOS equivalents follow where they differ.

> **Where to run these:** open a terminal **in the project folder** — the one
> that contains `docker-compose.yml`. In PowerShell you can `cd` there, e.g.
> `cd C:\Users\you\Downloads\HLPA-DS`.

---

## 0. One-time: install the prerequisite

You only need **Docker Desktop**. Everything else runs inside containers.

1. Download Docker Desktop: https://www.docker.com/products/docker-desktop/
2. Install it, then **launch it** and wait until it says *"Engine running"*.
3. Verify in PowerShell:

```powershell
docker version          # shows Client and Server versions
docker compose version  # should be v2.x
```

If `docker version` shows only *Client* and errors on *Server*, Docker Desktop
isn't running yet — open it and wait.

---

## 1. First run (do this once)

```powershell
# Step 1 — generate secrets and your login accounts into a .env file
.\scripts\setup.ps1

# Step 2 — build all the images and start every service in the background
docker compose up -d --build

# Step 3 — open the dashboard
start http://localhost:8080

# Step 4 — load demo data so the dashboard has something to show
.\scripts\replay-samples.ps1
```

**What each does:**

| Command | What it does |
|---|---|
| `.\scripts\setup.ps1` | Creates `.env` with random secrets and generated passwords for the `admin`, `analyst`, `viewer` accounts. **It prints the accounts — write them down.** Run it only once; it won't overwrite an existing `.env`. |
| `docker compose up -d --build` | Builds the decoys, collector, API, dashboard and controller images, then starts them. `-d` = background ("detached"), `--build` = rebuild images first. First run takes a few minutes. |
| `start http://localhost:8080` | Opens the dashboard in your browser. Sign in with the **admin** account from step 1. |
| `.\scripts\replay-samples.ps1` | Feeds synthetic sample logs through the pipeline so alerts DET-01–DET-08 appear. No attack traffic — just log records. |

> **Forgot your password?** It's in the `.env` file. Open it:
> `notepad .env` and look for `ADMIN_PASSWORD=`.

**Linux/macOS equivalent of step 1–2:**
```bash
./scripts/setup.sh
docker compose up -d --build
xdg-open http://localhost:8080      # macOS: open http://localhost:8080
docker compose run --rm replay --fresh-times
```

---

## 2. Everyday commands

```powershell
docker compose ps              # list services and their status (running/healthy)
docker compose up -d           # start the stack (no rebuild) — e.g. after a reboot
.\scripts\stop.ps1             # stop the stack, KEEP all data
.\scripts\stop.ps1 -Wipe       # stop the stack AND delete all stored data
docker compose restart         # restart every service
docker compose restart collector   # restart just one service (api, frontend, …)
```

| Command | What it does |
|---|---|
| `docker compose ps` | Shows each service and whether it's `running`, `healthy`, or `exited`. Your first check if something seems off. |
| `docker compose up -d` | Starts everything using images already built. Use this after you've stopped the stack or rebooted your PC. |
| `.\scripts\stop.ps1` | Stops all containers. Your data (events, alerts, users) is preserved in Docker volumes. |
| `.\scripts\stop.ps1 -Wipe` | Stops containers **and deletes the data volumes** — a completely fresh start next time. Use when you want to clear all events/alerts. |
| `docker compose restart <service>` | Restarts one service. Service names: `mongo`, `cowrie`, `opencanary`, `http-decoy`, `collector`, `controller`, `api`, `frontend`. |

---

## 3. Watching what's happening (logs)

```powershell
docker compose logs -f collector    # follow the detection engine live (Ctrl+C to stop)
docker compose logs -f api          # follow the API
docker compose logs --tail=50 cowrie    # last 50 lines from the SSH decoy
docker compose logs                 # all services at once
```

| Command | What it does |
|---|---|
| `docker compose logs -f <service>` | Streams that service's log live. `-f` = "follow". Press **Ctrl+C** to stop watching (it does NOT stop the service). |
| `docker compose logs --tail=50 <service>` | Shows just the last 50 lines — handy for a quick look. |

The collector log is the most interesting one: you'll see `ALERT …` lines each
time a rule fires.

---

## 4. The demo / sample data

```powershell
.\scripts\replay-samples.ps1              # default speed
.\scripts\replay-samples.ps1 -Speed 50    # faster
```

Or directly with Docker:

```powershell
docker compose run --rm replay --fresh-times --speed 20
```

| Command | What it does |
|---|---|
| `.\scripts\replay-samples.ps1` | Generates synthetic sensor logs and replays them into the pipeline. The dashboard fills with events and alerts within seconds. Safe to run repeatedly (it's additive and tests deduplication). |
| `--fresh-times` | Stamps the sample events as "just now" so they appear in the default 24-hour dashboard view. |
| `--speed N` | How fast records are written (higher = faster). |

---

## 5. Using the live decoys (hand-driven lab testing)

First enable the decoys in the dashboard: **Decoys → Enable… → tick the
isolation checklist → Confirm**. Then, from your own machine, interact with them.
These are the published loopback ports (see `.env` to change them):

```powershell
# SSH decoy (Cowrie) — try any username/password; it's a fake emulated shell
ssh -p 2222 root@127.0.0.1

# Telnet decoy
# (use any telnet client to 127.0.0.1 port 2223)

# Web decoy — open the fake router admin page in a browser
start http://localhost:8888

# FTP decoy (OpenCanary)
# connect any FTP client to 127.0.0.1 port 2121
```

| Command | What it does |
|---|---|
| `ssh -p 2222 root@127.0.0.1` | Connects to the Cowrie SSH decoy. Every login attempt and command is logged; enough failed logins raise **DET-01**, and commands like `wget`/`uname` raise **DET-04**. Nothing runs on a real system. |
| `start http://localhost:8888` | Opens the decoy's fake admin login. Submitting the form logs a (fingerprinted, never stored) credential attempt. |

Watch the alerts appear on the dashboard's Overview and Alerts pages.

> Only do this inside the authorized lab on your own machine, as your project
> guide permits.

---

## 6. Running the tests

```powershell
.\scripts\run-tests.ps1
```

| Command | What it does |
|---|---|
| `.\scripts\run-tests.ps1` | Runs both automated suites in containers: 35 collector/detection tests and 18 API tests. Expect `35 passed` and `18 passed`. |

Run them individually if you prefer:

```powershell
# Collector / detection tests only
docker compose run --rm --entrypoint "python" collector -m pytest tests/ -q

# API tests only
docker compose run --rm --entrypoint "sh" api -c "MONGO_URL=mongodb://mongo:27017 npm test"
```

---

## 7. Emergency stop (the kill switch)

```powershell
.\scripts\emergency-stop.ps1
```

| Command | What it does |
|---|---|
| `.\scripts\emergency-stop.ps1` | Immediately stops **all three decoy containers**. The dashboard, API and database keep running so you can still review what happened. Re-enable decoys from the Decoys page when it's safe. |

Equivalent manual command:
```powershell
docker stop hlpa-cowrie hlpa-opencanary hlpa-http-decoy
```

---

## 8. Resetting rules / re-seeding

```powershell
# Re-load the detection rules from rules.yml (discards dashboard tuning)
docker compose exec collector python -m hlpa_collector.main --reseed-rules
```

| Command | What it does |
|---|---|
| `docker compose exec collector …` | Runs a command **inside the already-running** collector container. `--reseed-rules` overwrites the rules in the database with the originals from `collector/rules/rules.yml`. |

---

## 9. Inspecting / troubleshooting

```powershell
docker compose ps                 # what's running
docker stats                      # live CPU / RAM per container (Ctrl+C to exit)
docker compose logs collector     # read a service's output
docker compose config             # validate docker-compose.yml + .env
docker compose down               # stop & remove containers (keeps data volumes)
docker compose down -v            # stop & remove containers AND data volumes
docker system df                  # how much disk Docker is using
docker system prune               # free space: remove unused images/containers (careful)
```

| Problem | Command to run |
|---|---|
| Something won't start | `docker compose ps` then `docker compose logs <service>` |
| "collector" dot is red/stale in the UI | `docker compose logs collector` — usually still starting or waiting for MongoDB |
| Port already in use error | Edit the `*_PORT` lines in `.env`, then `docker compose up -d` |
| Measure resource use (for your report) | `docker stats` while the stack runs |
| "no space left on device" | `docker system prune` to reclaim space |
| Want a totally clean slate | `.\scripts\stop.ps1 -Wipe` then `docker compose up -d --build` |

---

## 10. Command summary (copy-paste cheat sheet)

```powershell
# ---- first time ----
.\scripts\setup.ps1
docker compose up -d --build
start http://localhost:8080
.\scripts\replay-samples.ps1

# ---- day to day ----
docker compose ps
docker compose up -d
.\scripts\stop.ps1
docker compose logs -f collector

# ---- demo / test ----
.\scripts\replay-samples.ps1
.\scripts\run-tests.ps1

# ---- safety ----
.\scripts\emergency-stop.ps1

# ---- fresh start ----
.\scripts\stop.ps1 -Wipe
docker compose up -d --build
```

### Linux / macOS — same flow, different front door

```bash
./scripts/setup.sh
docker compose up -d --build
open http://localhost:8080            # Linux: xdg-open
docker compose run --rm replay --fresh-times
docker compose ps
docker compose logs -f collector
docker compose down                   # down -v to wipe data
./scripts/emergency-stop.sh
```

> PowerShell scripts (`.ps1`) are Windows-only. On Linux/macOS use the Docker
> commands shown above, plus `./scripts/setup.sh` and
> `./scripts/emergency-stop.sh`.
