# Final Report Checklist

Use this to assemble evidence for submission. Replace every placeholder with your
own details and **measured** results.

## Before you submit

- [ ] Add team member names to the **PRD cover page** and to this project's
      `README.md` tech-stack section.
- [ ] Run `.\scripts\setup.ps1` and record your account names (not the passwords)
      in the report appendix.
- [ ] Change the default passwords (Administration → Users) before any shared demo.

## Evidence to capture (use synthetic data in screenshots)

- [ ] **Startup (T-01):** screenshot of Administration → System status with API,
      collector, storage and all sources healthy.
- [ ] **Isolation (T-02):** Decoys page showing *egress: all outbound blocked* for
      each decoy, plus the terminal output of the blocked-egress command in
      `docs/TESTING.md`.
- [ ] **Ingestion completeness (T-03 / O-02):** the JSON from
      `GET /api/reports/ingestion-test?run_id=...` showing `completeness_pct` and
      `pass: true`.
- [ ] **Detection positive (T-05):** dashboard after `replay-samples`, showing
      `DET-01`–`DET-08`; open one alert's **Why this fired** panel.
- [ ] **Detection negative (T-06):** note that source `203.0.113.200` (benign)
      raised no high-severity alert.
- [ ] **Deduplication (T-07):** one alert with a high event count; the supporting
      events still listed.
- [ ] **Investigation & audit (T-08):** an alert moved through states with notes;
      the matching audit-log rows.
- [ ] **Authorization (T-09):** viewer blocked from an admin action; the audited
      denial.
- [ ] **Export (T-11):** a CSV opened in a spreadsheet showing the header block
      and a neutralised formula cell.
- [ ] **Recovery (T-14):** events present before and after `docker compose restart`.
- [ ] **Performance (T-15):** `detection_latency_ms` p50/p95 from
      `reports/summary`, and `docker stats` CPU/RAM for the run.
- [ ] **Automated tests:** terminal output of `.\scripts\run-tests.ps1`
      (35 collector + 18 API passing).

## Report sections (suggested)

1. Introduction & problem statement — from the PRD.
2. Objectives & scope — PRD 1.4 / 2.
3. Architecture — summarize `docs/ARCHITECTURE.md`; include the trust-zone
   diagram and the event-flow steps.
4. Implementation — components, detection rules, data model, security controls.
5. Testing & results — `docs/TESTING.md` procedures with **your measured numbers**.
6. Requirement traceability — reference `docs/PRD_TRACEABILITY.md`.
7. Limitations & future work — PRD 11 plus the "Known limitations" list.
8. Conclusion.
9. Appendices — setup steps, account list (no passwords), screenshots.

## Honesty note (from the PRD)

The PRD's targets are **acceptance criteria**, not claims of measured performance.
Report what your test runs actually produced, and list any acceptance test that
did not pass. Do not state a target as achieved without evidence.
