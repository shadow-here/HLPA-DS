"""Source adapters. Each adapter turns ONE raw log line into ONE normalized event dict.

Adapters must:
  * never invent values - fields a source does not provide stay None;
  * never return clear-text passwords (use redact.fingerprint);
  * raise ParseError for records that cannot be parsed (they are quarantined).
"""
from __future__ import annotations

from datetime import datetime, timezone


class ParseError(Exception):
    pass


def parse_time(value) -> datetime:
    """Parse the timestamp formats used by the supported sensors into aware UTC datetimes."""
    if value is None or value == "":
        raise ParseError("missing timestamp")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if "T" not in s and " " in s:
        s = s.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise ParseError(f"bad timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def base_event(source_type: str) -> dict:
    return {
        "source_type": source_type,
        "sensor_id": None,
        "event_time": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "service": None,
        "protocol": None,
        "event_category": "other",
        "outcome": "unknown",
        "session_id": None,
        "username": None,
        "credential_fp": None,
        "command": None,
        "http_method": None,
        "http_path": None,
        "http_status": None,
        "user_agent": None,
        "message": None,
        "tags": [],
        "parser_status": "parsed",
    }


def as_port(v):
    try:
        p = int(v)
        return p if 0 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


def as_ip(v):
    if not v or not isinstance(v, str) or len(v) > 64:
        return None
    return v.strip() or None
