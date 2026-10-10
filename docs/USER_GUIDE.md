# User Guide

The dashboard is at **http://localhost:8080**. Sign in with the account from
`setup.ps1`. Everything is role-aware: **viewer** can look, **analyst** can
investigate, **admin** can configure.

## Overview

The landing page summarizes the selected time window (1h / 24h / 7d / 30d):

- **Stat tiles:** total interaction events, open alerts, high/critical open,
  ingest errors.
- **Activity over time:** events (bars) and alerts created (line).
- **Open alerts by severity**, **decoy fleet health**, **top observed sources**,
  **detection-rule hits** (click any to drill into events/alerts).
- **Unresolved alerts** table — click a row to investigate.

## Alerts

Grouped, deduplicated detections. Filter by status (default **Open**), severity,
rule, source IP, or free text. Click an alert to open its detail:

- **Why this fired** — the rule, version, detection latency, the matched
  condition, and sample evidence fields. This is the explainability the PRD
  requires: you can always see *why* an alert exists.
- **Supporting events** — every event in the group, in order; open any in the
  event explorer.
- **Timeline & audit** — creation and every analyst action.
- **Investigate** (analyst+) — move the alert through its lifecycle:
  `New → Acknowledged → Investigating → Contained (lab only) / Resolved / False
  Positive`. Only valid transitions are offered; closing requires a note.
- **Lab-only response** (admin) — request a bounded lab block. The adapter is
  disabled by default, so the request is safely **refused** and audited; nothing
  on any network changes.

## Event explorer

Every normalized interaction. Filter by range, source type, category, service,
source IP, or text; hide heartbeat/system noise with the toggle. Click a row for
the full event, including the **sanitized raw record** (analysts and admins
only). Passwords are shown only as a fingerprint — never in clear text. Export
the filtered set to CSV/JSON (analyst+).

## Decoys

Inventory with type, address, ports, config version, health probes and the
egress self-test result.

- **Enable a decoy** (admin): complete the **isolation checklist** — the decoy
  cannot be enabled until every item is confirmed. A failed container start is
  reported and the decoy is **not** silently marked active.
- **Disable** stops the container. **Run health check** triggers an immediate
  probe. **Emergency stop all** is the kill switch.
- Watch the **egress self-test**: it should always read *all outbound blocked*.
  If it ever shows a succeeded connection, a critical `DET-08` alert is raised —
  disable the decoy and re-check the network.

## Administration

- **Detection rules** — enable/disable and tune severity, threshold and window.
  Each change bumps the rule version and is audit-logged.
- **Approved sources** — mark lab test clients so they don't create attacker
  alerts. Exclusions require a reason, expire automatically, and stay visible.
- **Indicators** — the local IOC list for `DET-07` (a match is a lead, not
  attribution).
- **Retention** — how long events/raw and alerts/audit are kept (the collector
  applies this hourly).
- **Users** (admin) — add/disable accounts and set roles.
- **Audit log** (admin) — every sign-in, config change, status change, export and
  response approval.
- **System status** — collector heartbeat and stats, per-source ingestion state,
  storage counts, and controller/container status.

## A typical triage flow

1. **Overview** shows a new high/critical count → open **Unresolved alerts**.
2. Open the alert → read **Why this fired** and the **supporting events**.
3. Decide: real test traffic? Add the source to **Approved sources**. Noise?
   Mark **False Positive** with a note. Worth tracking? **Acknowledge →
   Investigating**, add findings.
4. If policy allows a lab containment, request it (admin) — bounded and audited.
5. **Resolve** with a note. Everything you did is in the alert timeline and the
   audit log.
