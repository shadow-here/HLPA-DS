# Testing

Two automated suites plus the manual acceptance tests from the PRD (T-01…T-15).

## Automated tests

### Run inside Docker (recommended)

```powershell
.\scripts\run-tests.ps1
```

This runs both suites in containers against a disposable database.

### Run directly

**Collector / detection** (35 tests — parsers, detection, dedup, redaction,
taggers). Needs only Python; uses `mongomock`, so no database required:

```bash
cd collector
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

**API** (18 tests — auth, CSRF, authorization, alert lifecycle & audit,
injection, exports). Needs a reachable MongoDB:

```bash
cd api
npm install
MONGO_URL=mongodb://localhost:27017 npm test
```

If `MONGO_URL` is not set, the API suite skips with a clear message rather than
failing.

## What the automated tests cover

| Suite | File | Covers (PRD) |
|---|---|---|
| Parser robustness | `collector/tests/test_parsers.py` | T-04, FR-06, 6.1 — normalization, malformed input contained, secrets never survive parsing |
| Detection | `collector/tests/test_detection.py` | T-05/T-06/T-07, DET-01…DET-10 — positive & negative cases, windows, dedup, severity, latency |
| Redaction & taggers | `collector/tests/test_redact_tag.py` | 7.3 — fingerprinting, truncation, command/URL tagging with decode/case-folding |
| API behaviour | `api/test/api.test.js` | T-08 lifecycle & audit, T-09 authorization, T-10 injection/unsafe-render, T-11 export accuracy & formula-safety, FR-04 checklist, CSRF |

## Manual acceptance tests (PRD 8.3)

Run these for the final report; record actual results.

| ID | Test | How to run it here |
|---|---|---|
| **T-01** | Startup & health | `docker compose up -d`; dashboard **Administration → System status** shows API, collector, storage and each source **ok**. |
| **T-02** | Isolation validation | Enable the decoys. On **Decoys**, each shows an **egress self-test: all outbound blocked**. From a decoy: `docker compose exec http-decoy python -c "import socket;socket.create_connection(('8.8.8.8',443),3)"` → fails. |
| **T-03** | Event ingestion (100 events) | Replay a numbered run, then `GET /api/reports/ingestion-test?run_id=...` (see below). Target ≥ 95%. |
| **T-04** | Parser robustness | `pytest tests/test_parsers.py`; malformed inputs are quarantined in `ingest_errors`, worker keeps running. |
| **T-05** | Detection positive | `.\scripts\replay-samples.ps1` → `DET-01` (and others) appear within the latency target. |
| **T-06** | Detection negative | The sample set includes below-threshold benign traffic (`203.0.113.200`) which raises **no** high-severity alert. |
| **T-07** | Deduplication | Replay again; repeated matches update one alert and raise its event count — underlying events stay queryable in the event explorer. |
| **T-08** | Alert lifecycle & audit | Change an alert's status with a note; **Administration → Audit log** records actor/time/target/outcome. Invalid transitions are rejected. |
| **T-09** | Authorization | Sign in as `viewer`; admin actions are blocked (403) even if the API is called directly; the denial is audited. |
| **T-10** | Injection / unsafe render | Covered by the API suite; HTML-looking event fields render as text, query-operator injection is a no-op. |
| **T-11** | Export accuracy | Export events/alerts to CSV; header carries range + filters; formula-trigger cells are prefixed with `'`. |
| **T-12** | Notification failure | Notifications are not configured by default; alerts remain stored (nothing is lost). |
| **T-13** | Lab containment adapter | The lab response adapter is disabled by default; a response request is **refused** and audited (`state: not_applied`) — no network change. |
| **T-14** | Recovery | `docker compose restart`; stored events survive, ingestion resumes from the cursor without mass duplication. |
| **T-15** | Performance baseline | Replay a workload; read `GET /api/reports/summary` for `detection_latency_ms` p50/p95, and record container CPU/RAM from `docker stats`. |

### Ingestion completeness check (T-03 / O-02)

The HTTP decoy and the report endpoint support a numbered run. Generate 100
numbered web requests whose paths carry `?run=<id>&n=<1..100>` into the HTTP decoy
log, then:

```
GET /api/reports/ingestion-test?run_id=<id>&expected=100
```

It returns `completeness_pct`, the missing sequence numbers, and ingest-lag
percentiles, with `pass: true` at ≥ 95%. (The replay tool's flood scenario and
any numbered lab test you capture both feed this.)

## Expected automated result

```
collector:  35 passed
api:        18 passed
```
