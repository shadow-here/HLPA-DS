"""Cowrie JSON log adapter (output_jsonlog, one JSON object per line)."""
from __future__ import annotations

import json

from ..redact import fingerprint, truncate
from . import ParseError, as_ip, as_port, base_event, parse_time

CATEGORY_MAP = {
    "cowrie.session.connect": ("connection", "observed"),
    "cowrie.login.failed": ("auth_failure", "failed"),
    "cowrie.login.success": ("auth_success", "accepted"),
    "cowrie.command.input": ("session_command", "recorded"),
    "cowrie.command.failed": ("session_command", "unknown_command"),
    "cowrie.session.file_download": ("file_download", "emulated"),
    "cowrie.session.file_download.failed": ("file_download", "failed"),
    "cowrie.session.file_upload": ("file_upload", "emulated"),
    "cowrie.direct-tcpip.request": ("tunnel_request", "denied"),
    "cowrie.direct-tcpip.data": ("tunnel_request", "denied"),
    "cowrie.session.closed": ("session_closed", "closed"),
    "cowrie.client.version": ("session_meta", "observed"),
    "cowrie.client.kex": ("session_meta", "observed"),
    "cowrie.client.size": ("session_meta", "observed"),
    "cowrie.session.params": ("session_meta", "observed"),
    "cowrie.client.fingerprint": ("session_meta", "observed"),
    "cowrie.log.closed": ("session_meta", "observed"),
}


def parse(line: str) -> dict:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(rec, dict):
        raise ParseError("record is not a JSON object")
    eventid = rec.get("eventid")
    if not eventid or not isinstance(eventid, str):
        raise ParseError("missing eventid")

    ev = base_event("cowrie")
    ev["event_time"] = parse_time(rec.get("timestamp"))
    ev["sensor_id"] = str(rec.get("sensor") or "cowrie")[:64]
    ev["src_ip"] = as_ip(rec.get("src_ip"))
    ev["src_port"] = as_port(rec.get("src_port"))
    ev["dst_ip"] = as_ip(rec.get("dst_ip"))
    ev["dst_port"] = as_port(rec.get("dst_port"))
    proto = rec.get("protocol")
    if proto not in ("ssh", "telnet"):
        proto = "telnet" if ev["dst_port"] in (23, 2223) else "ssh"
    ev["service"] = proto
    ev["protocol"] = "tcp"
    ev["session_id"] = str(rec.get("session"))[:64] if rec.get("session") else None
    cat, outcome = CATEGORY_MAP.get(eventid, ("other", "unknown"))
    ev["event_category"] = cat
    ev["outcome"] = outcome
    ev["sensor_event"] = eventid[:64]

    if "username" in rec:
        ev["username"] = truncate(str(rec.get("username")), 128)
    if rec.get("password") not in (None, ""):
        ev["credential_fp"] = fingerprint(str(rec["password"]))
    if cat == "session_command":
        ev["command"] = truncate(str(rec.get("input", "")), 500)
    if cat in ("file_download", "file_upload"):
        ev["url"] = truncate(str(rec.get("url", "")), 500) or None
        ev["sha256"] = rec.get("shasum")
    if cat == "tunnel_request":
        ev["tunnel_dst"] = f"{rec.get('dst_ip', '')}:{rec.get('dst_port', '')}"

    # Human-readable summary built only from already-sanitized fields.
    if cat == "auth_failure":
        ev["message"] = f"Failed {proto} login for user '{ev['username']}'"
    elif cat == "auth_success":
        ev["message"] = f"Emulated {proto} login accepted for user '{ev['username']}'"
    elif cat == "session_command":
        ev["message"] = f"Command in emulated shell: {ev['command']}"
    elif cat == "connection":
        ev["message"] = f"New {proto} connection"
    else:
        ev["message"] = truncate(str(rec.get("message", eventid)), 300) if "password" not in rec else eventid

    if not ev["src_ip"]:
        ev["parser_status"] = "partial"
    return ev
