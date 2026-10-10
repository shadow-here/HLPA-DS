# PRD Traceability

Maps PRD requirements to where they are implemented, so an evaluator can verify
coverage. Paths are relative to the project root.

## Objectives (PRD 1.4)

| ID | Objective | Where |
|---|---|---|
| O-01 | Deploy decoys safely | `decoys/`, `docker-compose.yml` (lab_net `internal`), Decoys page checklist |
| O-02 | Collect useful telemetry (≥95%) | `collector/`, `GET /api/reports/ingestion-test` |
| O-03 | Detect representative behaviour | `collector/rules/rules.yml`, `collector/tests/test_detection.py` |
| O-04 | Reduce alert noise | dedup in `engine.py` `_upsert_alert`, approved-source suppression |
| O-05 | Operational visibility | `frontend/` (events, alerts, timeline, export) |
| O-06 | Maintain containment | `lab_net internal`, `DET-08`, alert-first default |
| O-07 | Buildable / resettable | `docker-compose.yml`, `scripts/` |

## Functional requirements (PRD 3.1)

| FR | Requirement | Where |
|---|---|---|
| FR-01 | Auth & access control (server-enforced) | `api/src/auth.js`, `routes/auth.js` |
| FR-02 | Decoy registry | `api/src/routes/decoys.js`, `config/decoys.json` |
| FR-03 | Decoy lifecycle; failed health visible | `routes/decoys.js` (`/status`), collector health checks |
| FR-04 | Exposure/isolation checklist before enable | `routes/decoys.js` `CHECKLIST`, Decoys page |
| FR-05 | Event ingestion + error recording | `collector/hlpa_collector/main.py`, `ingest_errors` |
| FR-06 | Event normalization | `collector/hlpa_collector/parsers/` |
| FR-07 | Detection rules with evidence | `engine.py`, `rules/rules.yml` |
| FR-08 | Correlation & deduplication | `engine.py` `_upsert_alert` |
| FR-09 | Alert lifecycle states | `util.js` `TRANSITIONS`, `routes/alerts.js` |
| FR-10 | Dashboard & search | `frontend/src/pages/` |
| FR-11 | Timeline & evidence | `AlertDetail.jsx`, `GET /api/alerts/:id` |
| FR-12 | Notifications (should) | notification status field present; adapter not configured → alerts retained |
| FR-13 | Exports & reporting | `routes/reports.js` (CSV/JSON + summary) |
| FR-14 | Audit trail | `api/src/audit.js`, used across routes |
| FR-15 | Lab-only response adapter (should) | `routes/alerts.js` response-request (disabled → refused), 7.4 gates |
| FR-16 | Health & system status | `GET /api/system/status`, `system_status` collection |
| FR-17 | Config management (should) | `rules.yml`, `indicators.yml`, `.env` (secrets excluded) |
| FR-18 | Optional network IDS (could) | adapter pattern in `parsers/` leaves a Suricata EVE path open |

## Detection catalogue (PRD 3.2)

All ten rules are implemented in `collector/rules/rules.yml` and exercised by
`collector/tests/test_detection.py` and the sample replay:

`DET-01` … `DET-10` — see `docs/ARCHITECTURE.md` §5 and the Admin → Detection
rules page. `DET-08` (isolation) and `DET-09` (health) are `kind: isolation` /
`monitoring` and are never suppressed.

## Non-functional requirements (PRD 3.3)

| NFR | Requirement | Where / how verified |
|---|---|---|
| NFR-01 | Detection latency ≤5s p95 | `detection_latency_ms` per alert; `reports/summary`; T-15 |
| NFR-02 | Ingestion ≥95%, errors counted | `reports/ingestion-test`, `ingest_errors` |
| NFR-03 | API p95 < 2s | indexed queries, pagination; measure with T-15 |
| NFR-04 | Usability | explainable alert detail, guided dashboard |
| NFR-05 | Security (authz, env secrets) | `auth.js`, `config.js` |
| NFR-06 | Isolation | `lab_net internal`, egress self-test, `DET-08` |
| NFR-07 | Recoverability | Docker volumes, ingest cursors; T-14 |
| NFR-08 | Maintainability | modular adapters/rules, test fixtures |
| NFR-09 | Privacy | redaction, raw access control, retention |
| NFR-10 | Auditability | `audit_log` with actor/action/target/time/outcome/reason |
| NFR-11 | Compatibility | Docker Compose; current browsers |
| NFR-12 | Resource usage | measure with `docker stats` during T-15 |

## Security & responsible operation (PRD 7)

See `docs/SECURITY.md` — isolation, identity, safe decoy content, response gates,
privacy, each mapped to 7.1–7.5.

## Test strategy (PRD 8.3)

See `docs/TESTING.md` — T-01…T-15 procedures and the automated suites that cover
T-04/T-05/T-06/T-07/T-08/T-09/T-10/T-11.

## Known limitations (be honest in the report)

- Notifications (FR-12) and the lab response adapter (FR-15) are scaffolded with
  safe defaults (disabled) rather than fully integrated — intentional for the
  alert-first MVP.
- `DET-03` port-probing needs connection telemetry; it uses OpenCanary/HTTP-decoy
  connection events, not SSH logs alone.
- Suricata (FR-18) is left as an adapter path, not a running service.
- PRD targets (latency, completeness) are acceptance criteria — report **measured**
  results from your own test runs, not these numbers as achieved.
