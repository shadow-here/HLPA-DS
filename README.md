# HLPA-DS — Honeypot Luring Prevention and Attack Detection System

A defensive, **alert-first** deception platform for a controlled lab. It deploys
isolated decoy services, collects their interaction telemetry, detects
attack-like behaviour with explainable rules, and presents prioritized alerts to
an analyst — while keeping real systems outside the honeypot trust boundary.

> Academic major project. Built to the accompanying PRD (`HLPA-DS-PRD-001`).
> It supplements security controls; it does not replace a firewall, EDR, SIEM or
> IR team. A source observation is a **lead for investigation, never attribution**.

---

## What it does

| Capability | Where |
|---|---|
| **Three decoy types** — SSH/Telnet (Cowrie), common services (OpenCanary: FTP/MySQL/Redis/MSSQL/VNC/Git), and a synthetic HTTP admin console + fake service-port listeners | `decoys/` |
| **Collector / detection worker** — tails sensor logs, normalizes them to one schema, redacts secrets, and evaluates 10 explainable rules | `collector/` |
| **REST API** — auth, role-based access, decoy registry + isolation checklist, alert workflow, reporting, exports, audit log | `api/` |
| **Analyst dashboard** — overview, event explorer, alert investigation with evidence & timeline, decoy inventory, administration | `frontend/` |
| **Decoy controller** — the only component with Docker access; starts/stops an allow-list of decoy containers | `controller/` |
| **Synthetic sample logs + replay** — fabricated records that exercise every rule for a demo or test (no attack traffic) | `samples/` |
| **Automated tests** — 35 collector + 18 API tests covering detection, dedup, redaction, authorization, injection and export safety | `collector/tests/`, `api/test/` |

### The ten detection rules (`collector/rules/rules.yml`)

`DET-01` repeated failed auth · `DET-02` multi-account guessing · `DET-03` port/service
probing · `DET-04` suspicious emulated-shell commands · `DET-05` web-path probing ·
`DET-06` high-frequency interaction · `DET-07` local indicator match · `DET-08`
isolation breach (unexpected egress) · `DET-09` sensor health failure · `DET-10`
re-interaction after lab containment.

Thresholds, windows, severities and enable/disable are tunable from the dashboard;
each change bumps the rule version and is audit-logged.

---

## Quick start (Windows + Docker Desktop)

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)
installed and running (WSL 2 backend recommended). ~8 GB RAM free.

Open **PowerShell** in the project folder:

```powershell
# 1. Generate secrets and a .env file (creates admin/analyst/viewer accounts)
.\scripts\setup.ps1

# 2. Build and start everything
docker compose up -d --build        # first build takes a few minutes

# 3. Open the dashboard
start http://localhost:8080
```

Sign in with the **admin** account printed by `setup.ps1` (also saved in `.env`).

```powershell
# 4. Fill the dashboard with demo data (synthetic logs, no attack traffic)
.\scripts\replay-samples.ps1
```

Within a few seconds the dashboard shows events and alerts for `DET-01`–`DET-08`.

**Enable the live decoys** (so hand-driven lab testing is captured): go to
**Decoys**, click **Enable…**, complete the isolation checklist, and confirm.

> Linux/macOS: use `./scripts/setup.sh` then the same `docker compose` commands.

Common commands:

```powershell
docker compose ps                 # service status
docker compose logs -f collector  # follow detection activity
.\scripts\stop.ps1                # stop (keeps data).  -Wipe to delete data
.\scripts\emergency-stop.ps1      # kill switch: stop all decoys now
.\scripts\run-tests.ps1           # run the automated test suites
```

---

## How it fits together

```
          (authorized lab test client / hand-driven interaction)
                               │
     ┌─────────────────────────┼──────────────────── lab_net (ISOLATED, no egress)
     │   Cowrie 10.66.0.10   OpenCanary 10.66.0.11   HTTP decoy 10.66.0.12
     │        │                   │                       │
     │        └──── JSON logs (shared read-only volumes) ──┘
     └─────────────────────────┬──────────────────────────────────────────
                               │ (collector reads logs, health-probes decoys)
     ┌─────────────────────────┼──────────────────── app_net
     │   collector/detection ──┼──► MongoDB ◄──── API ◄──── frontend (:8080)
     │                         │                    │
     │                   decoy controller ◄─────────┘   (start/stop decoys only)
     │                    (Docker socket)
     └───────────────────────────────────────────────────────────────────
                 production network is OUTSIDE this diagram — no route in
```

- **Isolation** is enforced by Docker: `lab_net` is `internal: true`, so decoys
  have **no outbound route**. The HTTP decoy runs a periodic egress self-test and
  raises a **critical `DET-08`** alert if any outbound connection ever succeeds.
- **Least privilege:** only the controller touches Docker; decoys run with
  `cap_drop: ALL` and `no-new-privileges`.
- **Secrets are never stored:** passwords submitted to decoys are kept only as a
  keyed, non-reversible fingerprint (so "same password reused" is visible without
  retaining the secret). Untrusted fields are escaped in the UI and never executed.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, trust
zones, data model and API reference.

---

## Documentation

| Doc | Contents |
|---|---|
| [`docs/COMMANDS.md`](docs/COMMANDS.md) | **Every command, what it does** — install, run, demo, test, stop, troubleshoot (Windows + Linux/macOS) |
| [`docs/SETUP.md`](docs/SETUP.md) | Detailed install, configuration, troubleshooting, start/stop/reset |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, trust zones, event/alert schema, REST API, tech stack |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Using the dashboard: triage, investigation, decoys, administration |
| [`docs/TESTING.md`](docs/TESTING.md) | How to run the tests and the acceptance-test (T-01…T-15) procedures |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Isolation, identity, safe decoy content, response gates, privacy |
| [`docs/PRD_TRACEABILITY.md`](docs/PRD_TRACEABILITY.md) | Requirement → implementation map (FR, NFR, DET, objectives) |
| [`docs/REPORT_CHECKLIST.md`](docs/REPORT_CHECKLIST.md) | What to capture for the final project report |

---

## Responsible use

This system is for an **authorized** lab you control. Do not expose the decoys to
networks you are not permitted to test, do not place real data or credentials in
them, and keep response actions lab-only. Public exposure needs separate
authorization and stricter egress review, and is not required for this project.

## Tech stack

React + Vite + Tailwind · Node.js + Express · Python collector · MongoDB · Cowrie
+ OpenCanary + custom HTTP decoy · Docker Compose. Fill in your team names in
`docs/REPORT_CHECKLIST.md` and the PRD cover page before submitting.
