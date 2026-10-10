# Architecture

## 1. Components

| Component | Tech | Responsibility |
|---|---|---|
| **Decoys** | Cowrie, OpenCanary, custom Python | Present deliberately fake services and log every interaction as JSON lines. |
| **Collector / detection worker** | Python 3.12 | Tail logs → parse → sanitize → normalize → tag → store → evaluate rules → health checks → retention. |
| **Database** | MongoDB 7 | Events, alerts, decoy registry, users, rules, indicators, audit log, raw records, system status. |
| **API** | Node.js 20 + Express | Authentication, RBAC, decoy lifecycle, alert workflow, reporting, exports, administration. |
| **Decoy controller** | Python (stdlib + docker SDK) | Token-gated start/stop/status for an allow-list of decoy containers. Only component with Docker access. |
| **Frontend** | React 18 + Vite + Tailwind, served by nginx | Analyst console. |

Each component is a separate container with a clear boundary (PRD 5.1: small,
modular services; minimum privilege; reproducible deployment).

## 2. Trust zones (PRD 5.4)

| Zone | Members | Network | Egress |
|---|---|---|---|
| **B — Decoy network** | Cowrie, OpenCanary, HTTP decoy, collector (probe leg) | `lab_net` (`10.66.0.0/24`, `internal: true`) | **None** — no gateway out |
| **C — Application network** | collector, API, MongoDB, controller | `app_net` | Normal |
| **D — Analyst access** | frontend (→ API) | `app_net`, host `:8080` | Browser only |
| **Production** | — | Not attached | No route in |

`internal: true` on `lab_net` is the enforced isolation: containers on it cannot
reach the internet, other Docker networks, or the host LAN. The HTTP decoy's
egress self-test continuously verifies this and raises `DET-08` (critical) if an
outbound connection ever succeeds.

## 3. End-to-end event flow (PRD 5.3)

1. An authorized lab client (or hand-driven test) contacts a decoy.
2. The decoy records the interaction as a JSON log line (only the fields that
   sensor actually captured).
3. The collector reads new lines from its stored per-file **cursor** (offset +
   inode), so restarts don't re-ingest; invalid lines go to `ingest_errors`
   (quarantine) with a reason, never silently dropped.
4. Each record is parsed by a source adapter, **sanitized** (secret-like fields
   fingerprinted), normalized to the common schema, and **tagged** (e.g.
   `cmd:download`, `web:probe`). Event ids are a UUID5 of the raw line, so the
   same line is **idempotent** (dedup on re-read).
5. The **rule engine** evaluates the event. Window rules query the event store
   for the rule's time window — so decisions are reproducible from stored data,
   not hidden in-memory counters.
6. A new alert is created or an existing open alert is updated (dedup by rule +
   group + window); every supporting event id is preserved.
7. The dashboard polls and refreshes. An analyst investigates and updates status;
   every change is audit-logged.

## 4. Normalized event schema (PRD 6.1)

Stored in `events`. Fields a source does not provide stay `null` (never invented).

| Field | Notes |
|---|---|
| `event_id` | UUID5 of `source:sha256(raw line)` — idempotency key |
| `event_time` / `ingested_at` | sensor time vs. collector time, both UTC |
| `source_type` | `cowrie` \| `opencanary` \| `http_decoy` \| `collector` |
| `sensor_id` / `decoy_id` | registered sensor & decoy references |
| `src_ip` / `src_port` / `dst_ip` / `dst_port` | observed endpoints (nullable) |
| `dst_endpoint` | `dst_ip:dst_port`, used for distinct-port counting |
| `service` / `protocol` | e.g. `ssh`/`tcp` |
| `event_category` | `connection`, `auth_failure`, `auth_success`, `session_command`, `web_request`, `egress_attempt`, `health`, … |
| `outcome` | sensor-defined (`failed`, `accepted`, `allowed`, `blocked`, …) |
| `username` | submitted username (synthetic accounts) |
| `credential_fp` | **keyed HMAC fingerprint** of a submitted secret — never the secret |
| `command` / `http_method` / `http_path` / `user_agent` | per-source detail |
| `tags` | rule/classification labels |
| `raw_ref` | pointer to the sanitized raw record (restricted access) |
| `approved_source` | true if `src_ip` is an active approved test client |
| `parser_status` | `parsed` \| `partial` |

The alert model (`alerts`) is documented in PRD 6.2 and implemented in
`collector/hlpa_collector/engine.py`: `rule_id`/`rule_version`, `title`,
`severity`, `status`, source/decoy context, `first_seen`/`last_seen`,
`event_count`/`event_ids`, `matched_evidence`, `analyst_notes`, `history`,
`detection_latency_ms`.

## 5. Detection engine

- **Deterministic & explainable** (no ML). Every alert records *why* it fired:
  the matched condition, the observed count vs. threshold, the window, and sample
  evidence fields.
- **Rule types:** `threshold` (count in window), `distinct` (distinct values in
  window), `match` (single event), `ioc` (indicator-list match), `post_response`
  (re-interaction after lab containment).
- **Deduplication:** matches for the same rule + group within a dedupe window
  update one alert; underlying events are always preserved.
- **Suppression:** approved test sources are excluded from attacker-kind rules
  (isolation/monitoring rules are never suppressed). Exclusions expire and are
  audited.
- **Taggers** normalize commands and URL paths (decode, lowercase) before
  pattern-matching, feeding `DET-04` and `DET-05`.

Rules are seeded from `collector/rules/rules.yml` on first start; after that they
are tuned from the dashboard (each edit bumps the version and is audited). Re-seed
with `docker compose exec collector python -m hlpa_collector.main --reseed-rules`.

## 6. REST API (PRD 6.4)

All `/api/*` routes except `GET /api/health` and `POST /api/auth/login` require a
session cookie. State-changing requests require the `X-Requested-With: hlpa`
header (CSRF defence). Roles: **viewer** < **analyst** < **admin**.

| Method & path | Role | Purpose |
|---|---|---|
| `POST /api/auth/login` · `/logout` · `GET /me` | public / any | session management (rate-limited login) |
| `GET /api/health` | public | non-sensitive health |
| `GET /api/system/status` | any | collector/storage/controller status (FR-16) |
| `GET /api/decoys` · `/:id` | any | registry + live container & health state |
| `POST /api/decoys` | admin | register decoy (validates lab CIDR & ports) |
| `PATCH /api/decoys/:id` | admin | edit metadata (bumps config version) |
| `PATCH /api/decoys/:id/status` | admin | enable (checklist) / disable / health-check |
| `POST /api/decoys/actions/emergency-stop` | admin | kill switch |
| `GET /api/events` · `/facets` · `/:id` | any | search; raw record is analyst+ only |
| `GET /api/alerts` · `/:id` | any | list / detail with evidence & timeline |
| `PATCH /api/alerts/:id` | analyst | status change / note (validated transitions) |
| `POST /api/alerts/:id/response-request` | admin | lab response (disabled → refused) |
| `GET /api/dashboard` · `/reports/summary` | any | overview & summary report |
| `GET /api/reports/ingestion-test` | analyst | 100-event completeness check (T-03) |
| `GET /api/exports/events` · `/alerts` · `/report` | analyst | CSV/JSON export (formula-safe) |
| `GET/PATCH /api/rules` · `/:id` | any / admin | detection catalogue & tuning |
| `/api/approved-sources` · `/api/indicators` | any / admin | suppression & IOC lists |
| `/api/users` · `/api/audit` | admin | user & audit management |
| `GET/PUT /api/settings/retention` | any / admin | retention policy |

## 7. Security properties

- Passwords (console users) stored as **bcrypt** hashes; secrets come from the
  environment, never source.
- Decoy-submitted credentials stored only as **keyed HMAC fingerprints**.
- Role checks enforced **on the server**, not just the UI; denials audited.
- Query parser set to "simple" so query values are strings — operator-injection
  (`?x[$ne]=`) can't build Mongo operators. Mongo queries are structured, never
  string-built.
- React escapes all rendered values; no `dangerouslySetInnerHTML`. nginx sets
  CSP, `X-Frame-Options`, `nosniff`.
- CSV exports prefix formula-trigger cells (`= + - @`) with `'` (PRD 6.3).
- Decoys: `cap_drop: ALL`, `no-new-privileges`, non-root, default-deny egress.

## 8. Technology stack (PRD 5.5)

React + Vite + Tailwind (dashboard) · Node.js + Express (API) · Python
(collector/detection) · MongoDB (store) · Cowrie + OpenCanary + custom HTTP decoy
· optional Suricata adapter path left open · Docker Compose on an isolated Linux
network. Versions are pinned in each component's manifest.
