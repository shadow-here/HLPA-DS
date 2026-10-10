"""OpenCanary JSON log adapter."""
from __future__ import annotations

import json

from ..redact import SECRET_KEY_RE, fingerprint, truncate
from . import ParseError, as_ip, as_port, base_event, parse_time

# logtype -> (service, category, outcome)
LOGTYPES = {
    1000: ("opencanary", "sensor_status", "observed"),
    1001: ("opencanary", "sensor_status", "observed"),
    1002: ("opencanary", "sensor_status", "observed"),
    1003: ("opencanary", "sensor_status", "error"),
    1004: ("opencanary", "sensor_status", "observed"),
    1005: ("opencanary", "sensor_status", "observed"),
    2000: ("ftp", "auth_failure", "failed"),
    2001: ("ftp", "connection", "observed"),
    3000: ("http", "web_request", "observed"),
    3001: ("http", "auth_failure", "failed"),
    4000: ("ssh", "connection", "observed"),
    4001: ("ssh", "session_meta", "observed"),
    4002: ("ssh", "auth_failure", "failed"),
    5000: ("smb", "file_access", "observed"),
    5001: ("portscan", "connection", "observed"),
    5002: ("portscan", "connection", "observed"),
    5003: ("portscan", "connection", "observed"),
    5004: ("portscan", "connection", "observed"),
    5005: ("portscan", "connection", "observed"),
    6001: ("telnet", "auth_failure", "failed"),
    6002: ("telnet", "connection", "observed"),
    7001: ("httpproxy", "auth_failure", "failed"),
    8001: ("mysql", "auth_failure", "failed"),
    9001: ("mssql", "auth_failure", "failed"),
    9002: ("mssql", "auth_failure", "failed"),
    9003: ("mysql", "connection", "observed"),
    10001: ("tftp", "file_access", "observed"),
    11001: ("ntp", "connection", "observed"),
    12001: ("vnc", "auth_failure", "failed"),
    13001: ("snmp", "connection", "observed"),
    14001: ("rdp", "connection", "observed"),
    15001: ("sip", "connection", "observed"),
    16001: ("git", "repo_request", "observed"),
    17001: ("redis", "session_command", "recorded"),
    18001: ("tcpbanner", "connection", "observed"),
    18002: ("tcpbanner", "connection", "observed"),
    18003: ("tcpbanner", "banner_data", "observed"),
    18004: ("tcpbanner", "banner_data", "observed"),
    18005: ("tcpbanner", "banner_data", "observed"),
    19001: ("llmnr", "connection", "observed"),
    20001: ("mongodb", "auth_failure", "failed"),
}


def parse(line: str) -> dict:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(rec, dict):
        raise ParseError("record is not a JSON object")
    if "logtype" not in rec:
        raise ParseError("missing logtype")
    try:
        logtype = int(rec["logtype"])
    except (TypeError, ValueError) as exc:
        raise ParseError("logtype is not an integer") from exc

    ev = base_event("opencanary")
    ev["event_time"] = parse_time(rec.get("utc_time") or rec.get("local_time"))
    ev["sensor_id"] = str(rec.get("node_id") or "opencanary")[:64]
    ev["src_ip"] = as_ip(rec.get("src_host"))
    ev["src_port"] = as_port(rec.get("src_port"))
    ev["dst_ip"] = as_ip(rec.get("dst_host"))
    ev["dst_port"] = as_port(rec.get("dst_port"))
    if ev["src_port"] == -1:
        ev["src_port"] = None
    service, cat, outcome = LOGTYPES.get(logtype, ("unknown", "other", "unknown"))
    ev["service"] = service
    ev["protocol"] = "udp" if service in ("snmp", "ntp", "tftp", "llmnr", "sip") else "tcp"
    ev["event_category"] = cat
    ev["outcome"] = outcome
    ev["sensor_event"] = f"opencanary.{logtype}"

    logdata = rec.get("logdata") or {}
    if not isinstance(logdata, dict):
        logdata = {}
    user = logdata.get("USERNAME") or logdata.get("USER")
    if user is not None:
        ev["username"] = truncate(str(user), 128)
    for k, v in logdata.items():
        if SECRET_KEY_RE.search(str(k)) and v not in (None, ""):
            ev["credential_fp"] = fingerprint(str(v))
            break
    if service == "redis":
        ev["command"] = truncate(f"{logdata.get('CMD', '')} {logdata.get('ARGS', '')}".strip(), 500)
    if service == "http":
        ev["http_path"] = truncate(str(logdata.get("PATH", "")), 2048) or None
        ev["user_agent"] = truncate(str(logdata.get("USERAGENT", "")), 512) or None
        ev["http_method"] = "POST" if logtype == 3001 else "GET"

    if cat == "sensor_status":
        msg = logdata.get("msg")
        if isinstance(msg, dict):
            msg = msg.get("logdata")
        ev["message"] = truncate(str(msg or f"OpenCanary status {logtype}"), 300)
    elif cat == "auth_failure":
        ev["message"] = f"{service.upper()} login attempt for user '{ev['username']}'"
    elif cat == "connection":
        ev["message"] = f"Connection to fake {service} service"
    elif cat == "session_command":
        ev["message"] = f"{service} command: {ev['command']}"
    else:
        ev["message"] = f"{service} interaction (logtype {logtype})"

    if cat != "sensor_status" and not ev["src_ip"]:
        ev["parser_status"] = "partial"
    return ev
