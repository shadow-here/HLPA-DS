# Security, Privacy & Responsible Operation

This maps to PRD section 7. The system is **defensive and alert-first**.

## Isolation (7.1)

- Decoys live on `lab_net`, a Docker network with `internal: true` — **no
  outbound route** to the internet, other Docker networks, or the host LAN.
- The collector joins `lab_net` only to health-probe decoys; it reads logs via
  read-only shared volumes.
- The HTTP decoy runs a periodic **egress self-test**. Any outbound connection
  that succeeds raises a **critical `DET-08`** alert and is shown on the Decoys
  page — this is continuous proof of isolation.
- Decoys run with `cap_drop: ALL`, `no-new-privileges`, and as non-root.
- The database, API and controller are never published to the host; only the
  dashboard port (`8080`) and the loopback-bound decoy ports are.

## Identity & access control (7.2)

- Console passwords are stored as **bcrypt** hashes (cost 12). Login is
  rate-limited; unknown users take the same time as wrong passwords.
- Sessions are JWTs in `httpOnly`, `sameSite=strict` cookies; set
  `COOKIE_SECURE=true` behind HTTPS.
- Roles (viewer/analyst/admin) are enforced **on the server** for every
  protected route; failed and denied attempts are audited.
- State-changing requests require the `X-Requested-With: hlpa` header (CSRF
  defence for cookie auth).
- Secrets (`JWT_SECRET`, `REDACTION_KEY`, `CONTROLLER_TOKEN`) come from `.env`,
  never source control.

## Safe decoy content (7.3)

- All decoy content is **synthetic**: fake hostnames, banners, accounts and a
  fabricated router-admin login page. No real credentials, keys or data.
- Passwords submitted to decoys are **never stored in clear text** — only a
  keyed HMAC-SHA256 fingerprint (so credential reuse is visible without keeping
  the secret). Any field whose key looks secret-like (`pass`, `token`, `secret`,
  …) is fingerprinted at ingestion, including inside raw records.
- Cowrie runs **emulation only** — no real shell, no proxy backend. Attacker
  "downloads" cannot succeed because egress is blocked; the MVP keeps no attacker
  files.
- All session commands, paths, headers and banners are treated as untrusted.
  React escapes every rendered value; there is no `dangerouslySetInnerHTML`.
  nginx sets a strict CSP, `X-Frame-Options: DENY`, and `nosniff`.
- Mongo queries are structured, never string-built; the API query parser is
  "simple" so query values can't smuggle in Mongo operators.

## Response safety gates (7.4)

| Control | Behaviour here |
|---|---|
| Default state | **Alert-only** — no automatic network changes. |
| Scope | A response adapter could target only a named lab firewall — never production. |
| Approval | Admin role + explicit confirmation of source/scope/duration/reason. |
| Expiry | Any lab block would be time-bounded with rollback. |
| Result verification | The UI distinguishes requested/applied/failed; it never claims success without confirmation. |
| Audit | Every request is recorded with actor/target/time/outcome/reason. |
| Kill switch | **Emergency stop** (dashboard or `emergency-stop.ps1`) stops all decoys at once. |

In this MVP the lab response adapter is **disabled**, so a response request is
refused (`state: not_applied`) and audited — demonstrating the gate without
touching any network. The system never executes attacker-supplied commands,
downloads/runs files, or forwards a session to a real machine.

## Privacy & data handling (7.5)

- Only metadata needed to explain an interaction is collected. Source addresses
  and request metadata are treated as sensitive operational data.
- **A source observation is a lead, not attribution.** The UI and rule wording
  avoid identifying a person or organization from a network indicator.
- Secret-like fields are redacted; raw records are access-controlled (analyst+)
  and excluded from the viewer role.
- Retention is bounded (default 30 days events/raw, 90 days alerts/audit) and
  applied automatically; reports note when a range predates the retention window.
- CSV exports neutralise spreadsheet formula injection and carry their range,
  generation time and applied filters.

## Responsible-use boundary

Use only within an **authorized** lab you control. Do not test third-party
systems, do not place real data in decoys, and keep any response lab-only. Public
exposure requires separate authorization and stricter egress review, and is not
needed for this project.
