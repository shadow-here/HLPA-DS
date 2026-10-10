"""
HLPA-DS decoy controller (sidecar).

This is the ONLY component with access to the Docker socket. It exposes a tiny,
token-protected HTTP API that can start, stop and report status for a fixed
ALLOW-LIST of decoy containers - nothing else. The API server never touches
Docker directly; it calls this service. That keeps Docker privileges out of the
internet-facing application and bounds what any response action can do.

Endpoints (require header X-Controller-Token):
    GET  /status                      -> state of every allow-listed container
    POST /containers/<name>/start     -> start one allow-listed container
    POST /containers/<name>/stop      -> stop one allow-listed container

Only names in ALLOWED_CONTAINERS are accepted; any other name is refused.
"""
from __future__ import annotations

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import docker

TOKEN = os.environ.get("CONTROLLER_TOKEN", "")
PORT = int(os.environ.get("CONTROLLER_PORT", "9000"))
ALLOWED = {c.strip() for c in os.environ.get("ALLOWED_CONTAINERS", "").split(",") if c.strip()}
STOP_TIMEOUT = int(os.environ.get("STOP_TIMEOUT", "10"))

_client = None


def client():
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def container_state(name):
    try:
        c = client().containers.get(name)
        return {"state": c.status, "status": c.attrs.get("State", {}).get("Status"), "health":
                c.attrs.get("State", {}).get("Health", {}).get("Status")}
    except docker.errors.NotFound:
        return {"state": "not found"}
    except Exception as exc:  # docker daemon unreachable etc.
        return {"state": "error", "error": str(exc)[:200]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # quiet

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        if not TOKEN:
            self._send(503, {"error": "controller token not configured"})
            return False
        if self.headers.get("X-Controller-Token") != TOKEN:
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        if not self._authorized():
            return
        if urlparse(self.path).path == "/status":
            return self._send(200, {"containers": {n: container_state(n) for n in sorted(ALLOWED)},
                                    "allowed": sorted(ALLOWED)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        # /containers/<name>/<action>
        if len(parts) != 3 or parts[0] != "containers":
            return self._send(404, {"error": "not found"})
        name, action = parts[1], parts[2]
        if name not in ALLOWED:
            return self._send(403, {"error": f"container '{name}' is not in the allow-list"})
        if action not in ("start", "stop"):
            return self._send(400, {"error": "action must be start or stop"})
        try:
            c = client().containers.get(name)
            if action == "start":
                c.start()
            else:
                c.stop(timeout=STOP_TIMEOUT)
            return self._send(200, {"ok": True, "container": name, "action": action, "state": container_state(name)})
        except docker.errors.NotFound:
            return self._send(404, {"error": f"container '{name}' not found"})
        except Exception as exc:
            return self._send(502, {"error": str(exc)[:200]})


def main():
    if not TOKEN:
        print("[controller] WARNING: CONTROLLER_TOKEN is empty - all requests will be refused")
    print(f"[controller] listening on :{PORT}; allow-list = {sorted(ALLOWED)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
