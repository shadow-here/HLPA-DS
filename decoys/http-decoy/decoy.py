"""
HLPA-DS HTTP / banner decoy.

A deliberately fake, low-interaction service used as a lure inside the isolated
lab network. It:

  * serves a synthetic "router admin console" login page on the HTTP port(s);
  * opens fake TCP banner listeners on a set of common service ports so that
    port/service probing produces connection telemetry (DET-03);
  * writes one JSON object per line to a log file that the collector tails;
  * NEVER stores submitted passwords - only a keyed, truncated, non-reversible
    fingerprint and the length are logged (PRD 2.5 / 7.3);
  * periodically runs an egress self-test and logs whether outbound
    connections are blocked (isolation evidence, feeds DET-08);
  * emits a heartbeat so the collector can tell the sensor is alive.

All content served here is synthetic. Nothing an interacting client sends is
ever executed.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import signal
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone

SENSOR_ID = os.environ.get("SENSOR_ID", "http-decoy-01")
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/hlpa/http_decoy.json")
BIND = os.environ.get("BIND_ADDRESS", "0.0.0.0")
HTTP_PORTS = [int(p) for p in os.environ.get("HTTP_PORTS", "80").split(",") if p.strip()]
LISTENER_PORTS = os.environ.get(
    "LISTENER_PORTS",
    "25,53,110,135,139,143,445,3389,5432,5900,8080,8443,9200,11211",
)
REDACTION_KEY = os.environ.get("REDACTION_KEY", "change-me-lab-only").encode()
HEARTBEAT_SECONDS = int(os.environ.get("HEARTBEAT_SECONDS", "30"))
EGRESS_CHECK_SECONDS = int(os.environ.get("EGRESS_CHECK_SECONDS", "300"))
EGRESS_TARGETS = os.environ.get(
    "EGRESS_TARGETS",
    "1.1.1.1:53,8.8.8.8:443,example.com:443,api:4000,mongo:27017,host.docker.internal:80",
)
MAX_HEADER_BYTES = 8192
MAX_BODY_BYTES = 8192

# Fake banners so the listeners look like plausible services. Purely cosmetic.
BANNERS = {
    21: b"220 FTP server ready\r\n",
    25: b"220 mail.corp-lab.local ESMTP Postfix (Ubuntu)\r\n",
    110: b"+OK POP3 server ready\r\n",
    143: b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n",
    5432: b"",
    5900: b"RFB 003.008\n",
    9200: b"",
    11211: b"",
}
SERVICE_NAMES = {
    25: "smtp", 53: "dns", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    445: "smb", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
}

_log_fh = None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def log_event(event: dict) -> None:
    """Append one JSON line. Values are plain data; nothing is interpreted."""
    global _log_fh
    event = {"ts": utcnow(), "sensor_id": SENSOR_ID, **event}
    line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
    if _log_fh is None:
        os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
        _log_fh = open(LOG_FILE, "a", buffering=1, encoding="utf-8")
    _log_fh.write(line + "\n")
    _log_fh.flush()


def credential_fingerprint(secret: str) -> str:
    """Keyed, truncated HMAC: lets analysts see 'same password reused' without storing it."""
    return hmac.new(REDACTION_KEY, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]


def safe_preview(data: bytes, limit: int = 200) -> str:
    """Printable-only preview of untrusted bytes (never decoded as markup or code)."""
    out = []
    for b in data[:limit]:
        if 32 <= b < 127:
            out.append(chr(b))
        elif b in (9, 10, 13):
            out.append(" ")
        else:
            out.append(".")
    return "".join(out)


def peer(writer: asyncio.StreamWriter):
    p = writer.get_extra_info("peername") or ("", 0)
    s = writer.get_extra_info("sockname") or ("", 0)
    return p[0], p[1], s[0], s[1]


# --------------------------------------------------------------------------- HTTP

LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>NX-2200 Edge Router - Management</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#eef1f4;margin:0}
.box{width:340px;margin:90px auto;background:#fff;border:1px solid #ccd3da;padding:28px 30px;border-radius:4px}
h1{font-size:18px;margin:0 0 4px;color:#1d3557}p.s{color:#6b7785;font-size:12px;margin:0 0 18px}
label{font-size:13px;color:#333}input{width:100%;padding:8px;margin:4px 0 12px;border:1px solid #bbb;box-sizing:border-box}
button{background:#1d3557;color:#fff;border:0;padding:9px 16px;cursor:pointer;width:100%}
.f{font-size:11px;color:#98a2ad;text-align:center;margin-top:16px}.e{color:#b00020;font-size:13px;margin-bottom:10px}
</style></head><body><div class="box">
<h1>NX-2200 Edge Router</h1><p class="s">Management Console &middot; firmware 3.2.14</p>
{error}
<form method="POST" action="/login">
<label>Username</label><input name="username" autocomplete="off">
<label>Password</label><input name="password" type="password" autocomplete="off">
<button type="submit">Sign in</button></form>
<div class="f">&copy; NetEdge Systems (synthetic lab asset)</div></div></body></html>"""

NOT_FOUND = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0</center></body></html>"
FORBIDDEN = "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx/1.18.0</center></body></html>"
ROBOTS = "User-agent: *\nDisallow: /backup/\nDisallow: /admin-old/\nDisallow: /cgi-bin/\n"


def http_response(status: int, body: str, ctype: str = "text/html; charset=utf-8") -> bytes:
    reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
              400: "Bad Request", 405: "Method Not Allowed", 413: "Payload Too Large"}.get(status, "OK")
    raw = body.encode()
    head = (
        f"HTTP/1.1 {status} {reason}\r\nServer: nginx/1.18.0\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(raw)}\r\nConnection: close\r\nX-Frame-Options: DENY\r\n\r\n"
    )
    return head.encode() + raw


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    src_ip, src_port, dst_ip, dst_port = peer(writer)
    status = 400
    method = path = ua = ""
    extra: dict = {}
    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except asyncio.LimitOverrunError:
            writer.write(http_response(413, "too large"))
            log_event({"type": "http_request", "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                       "dst_port": dst_port, "method": "", "path": "", "status": 413, "note": "oversized headers"})
            return
        if len(head) > MAX_HEADER_BYTES:
            head = head[:MAX_HEADER_BYTES]
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            method, path = parts[0][:16], parts[1][:2048]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()[:512]
        ua = headers.get("user-agent", "")
        body = b""
        clen = int(headers.get("content-length", "0") or 0) if headers.get("content-length", "0").isdigit() else 0
        if clen:
            body = await asyncio.wait_for(reader.readexactly(min(clen, MAX_BODY_BYTES)), timeout=10)

        route = urllib.parse.urlsplit(path).path or "/"
        if method == "GET" and route in ("/", "/login", "/index.html"):
            status, resp = 200, http_response(200, LOGIN_PAGE.replace("{error}", ""))
        elif method == "POST" and route == "/login":
            form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
            username = (form.get("username", [""])[0])[:128]
            password = form.get("password", [""])[0]
            log_event({
                "type": "login_attempt", "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                "dst_port": dst_port, "path": route, "username": username,
                "credential_fp": credential_fingerprint(password) if password else None,
                "credential_len": len(password), "outcome": "failed", "user_agent": ua,
            })
            password = None  # drop the value immediately
            status = 401
            resp = http_response(401, LOGIN_PAGE.replace("{error}", '<div class="e">Invalid username or password.</div>'))
        elif route == "/robots.txt":
            status, resp = 200, http_response(200, ROBOTS, "text/plain")
        elif route.startswith("/backup") or route.startswith("/admin-old"):
            status, resp = 403, http_response(403, FORBIDDEN)
        elif method not in ("GET", "POST", "HEAD"):
            status, resp = 405, http_response(405, NOT_FOUND)
        else:
            status, resp = 404, http_response(404, NOT_FOUND)
        writer.write(resp)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        extra["note"] = "incomplete request"
    except Exception as exc:  # never crash the decoy on hostile input
        extra["note"] = f"handler error: {type(exc).__name__}"
    finally:
        if method or extra:
            log_event({"type": "http_request", "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                       "dst_port": dst_port, "method": method, "path": path, "status": status,
                       "user_agent": ua, **extra})
        try:
            writer.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- banner listeners

def make_banner_handler(port: int):
    service = SERVICE_NAMES.get(port, f"tcp-{port}")

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        src_ip, src_port, dst_ip, dst_port = peer(writer)
        log_event({"type": "connection", "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                   "dst_port": dst_port, "service": service})
        try:
            banner = BANNERS.get(port, b"")
            if banner:
                writer.write(banner)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            if data:
                log_event({"type": "banner_data", "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                           "dst_port": dst_port, "service": service, "bytes": len(data),
                           "data_preview": safe_preview(data)})
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    return handler


# --------------------------------------------------------------------------- self checks

def _try_connect(target: str, timeout: float = 3.0) -> tuple[str, str]:
    host, _, port = target.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return "allowed", "connected"
    except socket.gaierror:
        return "blocked", "name resolution failed"
    except (socket.timeout, TimeoutError):
        return "blocked", "timed out"
    except OSError as exc:
        return "blocked", (exc.strerror or type(exc).__name__)


async def egress_loop():
    targets = [t.strip() for t in EGRESS_TARGETS.split(",") if t.strip()]
    while True:
        loop = asyncio.get_running_loop()
        for target in targets:
            outcome, detail = await loop.run_in_executor(None, _try_connect, target)
            log_event({"type": "egress_check", "target": target, "outcome": outcome, "detail": detail})
        await asyncio.sleep(EGRESS_CHECK_SECONDS)


async def heartbeat_loop(ports: list[int]):
    while True:
        log_event({"type": "heartbeat", "listening_ports": ports})
        await asyncio.sleep(HEARTBEAT_SECONDS)


async def main():
    servers = []
    ports_ok = []
    for port in HTTP_PORTS:
        try:
            servers.append(await asyncio.start_server(handle_http, BIND, port, limit=MAX_HEADER_BYTES * 2))
            ports_ok.append(port)
        except OSError as exc:
            log_event({"type": "sensor_error", "detail": f"cannot bind http {port}: {exc.strerror}"})
    for p in [int(x) for x in LISTENER_PORTS.split(",") if x.strip()]:
        try:
            servers.append(await asyncio.start_server(make_banner_handler(p), BIND, p))
            ports_ok.append(p)
        except OSError as exc:
            log_event({"type": "sensor_error", "detail": f"cannot bind {p}: {exc.strerror}"})
    log_event({"type": "sensor_start", "listening_ports": ports_ok})
    print(f"[http-decoy] {SENSOR_ID} listening on {ports_ok}, logging to {LOG_FILE}", flush=True)

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    tasks = [asyncio.create_task(heartbeat_loop(ports_ok)), asyncio.create_task(egress_loop())]
    await stop.wait()
    log_event({"type": "sensor_stop"})
    for t in tasks:
        t.cancel()
    for s in servers:
        s.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
