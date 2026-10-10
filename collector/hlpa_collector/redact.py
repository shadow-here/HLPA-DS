"""Redaction helpers: secret-like values never reach the event store in clear text."""
from __future__ import annotations

import hashlib
import hmac
import os
import re

_KEY = os.environ.get("REDACTION_KEY", "change-me-lab-only").encode()

SECRET_KEY_RE = re.compile(r"pass|secret|token|apikey|api_key|challenge|response|auth|cookie", re.I)
MAX_STR = 1000


def fingerprint(value: str) -> str:
    """Keyed, truncated HMAC-SHA256 - non-reversible, but equal inputs give equal output."""
    return hmac.new(_KEY, str(value).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]


def set_key(key: str) -> None:
    global _KEY
    _KEY = key.encode()


def truncate(value, limit: int = MAX_STR):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "...[truncated]"
    return value


def sanitize(obj, depth: int = 0):
    """Return a copy of a raw record with secret-like fields replaced and long strings cut."""
    if depth > 6:
        return "[nested too deep]"
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:100]:
            key = str(k)[:100]
            if SECRET_KEY_RE.search(key) and isinstance(v, (str, int, float)) and str(v) != "":
                out[key] = f"[redacted fp:{fingerprint(str(v))} len:{len(str(v))}]"
            else:
                out[key] = sanitize(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [sanitize(v, depth + 1) for v in obj[:100]]
    return truncate(obj)
