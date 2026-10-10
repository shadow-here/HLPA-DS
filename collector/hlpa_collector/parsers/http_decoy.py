"""Adapter for the HLPA-DS HTTP/banner decoy JSON log."""
from __future__ import annotations

import json

from ..redact import truncate
from . import ParseError, as_ip, as_port, base_event, parse_time

TYPE_MAP = {
    "http_request": ("http", "web_request"),
    "login_attempt": ("http", "auth_failure"),
    "connection": (None, "connection"),
    "banner_data": (None, "banner_data"),
    "heartbeat": ("decoy", "heartbeat"),
    "sensor_start": ("decoy", "sensor_status"),
    "sensor_stop": ("decoy", "sensor_status"),
    "sensor_error": ("decoy", "sensor_status"),
    "egress_check": ("decoy", "egress_attempt"),
}


def parse(line: str) -> dict:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(rec, dict):
        raise ParseError("record is not a JSON object")
    etype = rec.get("type")
    if etype not in TYPE_MAP:
        raise ParseError(f"unknown record type: {str(etype)[:40]!r}")

    service, cat = TYPE_MAP[etype]
    ev = base_event("http_decoy")
    ev["event_time"] = parse_time(rec.get("ts"))
    ev["sensor_id"] = str(rec.get("sensor_id") or "http-decoy")[:64]
    ev["src_ip"] = as_ip(rec.get("src_ip"))
    ev["src_port"] = as_port(rec.get("src_port"))
    ev["dst_ip"] = as_ip(rec.get("dst_ip"))
    ev["dst_port"] = as_port(rec.get("dst_port"))
    ev["service"] = rec.get("service") or service or "http"
    ev["protocol"] = "tcp"
    ev["event_category"] = cat
    ev["sensor_event"] = f"http_decoy.{etype}"

    if etype == "http_request":
        ev["http_method"] = truncate(str(rec.get("method", "")), 16) or None
        ev["http_path"] = truncate(str(rec.get("path", "")), 2048) or None
        ev["http_status"] = rec.get("status") if isinstance(rec.get("status"), int) else None
        ev["user_agent"] = truncate(str(rec.get("user_agent", "")), 512) or None
        ev["outcome"] = str(ev["http_status"]) if ev["http_status"] else "unknown"
        ev["message"] = f"{ev['http_method'] or '?'} {ev['http_path'] or ''} -> {ev['http_status']}"
    elif etype == "login_attempt":
        ev["username"] = truncate(str(rec.get("username", "")), 128)
        ev["credential_fp"] = rec.get("credential_fp")
        ev["http_path"] = rec.get("path")
        ev["http_method"] = "POST"
        ev["user_agent"] = truncate(str(rec.get("user_agent", "")), 512) or None
        ev["outcome"] = "failed"
        ev["message"] = f"Web console login attempt for user '{ev['username']}'"
    elif etype == "connection":
        ev["outcome"] = "observed"
        ev["message"] = f"TCP connection to fake {ev['service']} listener on port {ev['dst_port']}"
    elif etype == "banner_data":
        ev["outcome"] = "observed"
        ev["data_preview"] = truncate(str(rec.get("data_preview", "")), 200)
        ev["message"] = f"{rec.get('bytes', 0)} bytes sent to fake {ev['service']} listener"
    elif etype == "egress_check":
        ev["outcome"] = "allowed" if rec.get("outcome") == "allowed" else "blocked"
        ev["egress_target"] = truncate(str(rec.get("target", "")), 200)
        ev["message"] = f"Egress self-test to {ev['egress_target']}: {ev['outcome']} ({truncate(str(rec.get('detail', '')), 100)})"
    elif etype == "heartbeat":
        ev["outcome"] = "ok"
        ev["message"] = "Decoy heartbeat"
    else:
        ev["outcome"] = "error" if etype == "sensor_error" else "observed"
        ev["message"] = truncate(str(rec.get("detail") or etype), 300)

    if cat in ("web_request", "auth_failure", "connection", "banner_data") and not ev["src_ip"]:
        ev["parser_status"] = "partial"
    return ev
