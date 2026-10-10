"""HLPA-DS collector / detection worker.

Loop:
  1. tail every configured sensor log from its stored cursor (offset),
  2. parse -> sanitize -> normalize -> tag -> store (idempotent event ids),
  3. evaluate detection rules for every newly stored event,
  4. run decoy health checks, write a heartbeat, apply retention.

Invalid records are quarantined in `ingest_errors` with a reason (never silently dropped).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import yaml
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError

from . import redact
from .engine import RuleEngine, Tagger, aware
from .parsers import ParseError
from .parsers import cowrie as p_cowrie
from .parsers import http_decoy as p_http
from .parsers import opencanary as p_canary

log = logging.getLogger("hlpa.collector")

PARSERS = {"cowrie": p_cowrie.parse, "opencanary": p_canary.parse, "http_decoy": p_http.parse}
EVENT_NS = uuid.UUID("6f1c2a5e-1b7d-4c55-9a43-1d1f2f0f4a10")
MAX_LINE = 64 * 1024
READ_CHUNK = 1024 * 1024


def env(name, default):
    return os.environ.get(name, default)


MONGO_URL = env("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB = env("MONGO_DB", "hlpa")
SOURCES = env("SOURCES", "cowrie=/logs/cowrie/cowrie.json,opencanary=/logs/opencanary/opencanary.log,http_decoy=/logs/http/http_decoy.json")
RULES_FILE = env("RULES_FILE", os.path.join(os.path.dirname(__file__), "..", "rules", "rules.yml"))
INDICATORS_FILE = env("INDICATORS_FILE", os.path.join(os.path.dirname(__file__), "..", "rules", "indicators.yml"))
POLL_SECONDS = float(env("POLL_SECONDS", "1"))
HEALTH_SECONDS = int(env("HEALTH_SECONDS", "15"))
HEALTH_FAILS_BEFORE_ALERT = int(env("HEALTH_FAILS_BEFORE_ALERT", "3"))
HEALTH_PROBE_SOURCE_IP = env("HEALTH_PROBE_SOURCE_IP", "")
HEALTH_PROBE_BIND_IP = env("HEALTH_PROBE_BIND_IP", "")
HEARTBEAT_STALE_SECONDS = int(env("HEARTBEAT_STALE_SECONDS", "120"))


def utcnow():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- database

def connect():
    for attempt in range(60):
        try:
            client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=3000, tz_aware=True)
            client.admin.command("ping")
            return client[MONGO_DB]
        except PyMongoError as exc:
            log.warning("waiting for database (%s/60): %s", attempt + 1, exc)
            time.sleep(2)
    log.error("database unreachable, exiting")
    sys.exit(1)


def ensure_indexes(db):
    db.events.create_index([("event_time", DESCENDING)])
    db.events.create_index([("src_ip", ASCENDING), ("event_time", DESCENDING)])
    db.events.create_index([("decoy_id", ASCENDING), ("event_time", DESCENDING)])
    db.events.create_index([("event_category", ASCENDING), ("event_time", DESCENDING)])
    db.events.create_index([("source_type", ASCENDING)])
    db.events.create_index([("tags", ASCENDING)])
    db.events.create_index([("alert_ids", ASCENDING)])
    db.alerts.create_index([("status", ASCENDING), ("severity", ASCENDING)])
    db.alerts.create_index([("last_seen", DESCENDING)])
    db.alerts.create_index([("rule_id", ASCENDING), ("group_key", ASCENDING)])
    db.alerts.create_index([("src_ip", ASCENDING)])
    db.ingest_errors.create_index([("at", DESCENDING)])
    db.raw_events.create_index([("stored_at", ASCENDING)])


def seed_rules(db, reseed=False):
    with open(RULES_FILE, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    now = utcnow()
    for r in cfg.get("rules", []):
        doc = {**r, "_id": r["id"], "updated_at": now, "updated_by": "seed:rules.yml"}
        if reseed:
            db.rules.replace_one({"_id": r["id"]}, doc, upsert=True)
        elif not db.rules.find_one({"_id": r["id"]}):
            db.rules.insert_one(doc)
    db.settings.update_one({"_id": "taggers"}, {"$set": {"taggers": cfg.get("taggers", []), "updated_at": now}}, upsert=True)
    return cfg.get("taggers", [])


def seed_indicators(db):
    if db.indicators.count_documents({}) or not os.path.exists(INDICATORS_FILE):
        return
    with open(INDICATORS_FILE, encoding="utf-8") as fh:
        items = (yaml.safe_load(fh) or {}).get("indicators", [])
    now = utcnow()
    for it in items:
        db.indicators.insert_one({"value": str(it["value"]).lower(), "type": it.get("type", "ip"),
                                  "label": it.get("label", ""), "created_by": "seed:indicators.yml", "created_at": now})


# --------------------------------------------------------------------------- collector

class Collector:
    def __init__(self, db):
        self.db = db
        self.sources = []
        for item in SOURCES.split(","):
            if "=" in item:
                name, path = item.split("=", 1)
                self.sources.append((name.strip(), path.strip()))
        self.engine = RuleEngine(db)
        self.tagger = Tagger([])
        self.decoys_by_source: dict[str, dict] = {}
        self.approved: set[str] = set()
        self.stats = {"events_ingested": 0, "parse_errors": 0, "duplicates": 0, "probe_filtered": 0,
                      "alerts_touched": 0, "started_at": utcnow()}
        self.source_status = {}
        self.last_event_at = None
        self._last_refresh = 0
        self._last_health = 0
        self._last_heartbeat = 0
        self._last_retention = 0
        self.health_state: dict[str, dict] = {}

    # ---- caches
    def refresh(self, force=False):
        if not force and time.time() - self._last_refresh < 5:
            return
        self._last_refresh = time.time()
        rules = list(self.db.rules.find({}))
        taggers = (self.db.settings.find_one({"_id": "taggers"}) or {}).get("taggers", [])
        self.tagger = Tagger(taggers)
        indicators = {d["value"].lower() for d in self.db.indicators.find({}, {"value": 1}) if d.get("value")}
        self.engine.load(rules, indicators)
        now = utcnow()
        self.approved = set()
        for a in self.db.approved_sources.find({}):
            exp = aware(a.get("expires_at"))
            if exp is None or exp > now:
                self.approved.add(a["ip"])
        self.decoys_by_source = {}
        for d in self.db.decoys.find({}):
            self.decoys_by_source.setdefault(d.get("source_type"), d)

    # ---- tailing
    def poll_sources(self) -> int:
        total = 0
        for name, path in self.sources:
            try:
                total += self._read_source(name, path)
            except Exception as exc:
                log.exception("source %s failed", name)
                self.source_status[name] = {"path": path, "state": "error", "error": str(exc)[:200], "at": utcnow()}
        return total

    def _read_source(self, name, path) -> int:
        if not os.path.exists(path):
            self.source_status[name] = {"path": path, "state": "waiting for log file", "at": utcnow()}
            return 0
        st = os.stat(path)
        cur = self.db.ingest_cursors.find_one({"_id": name}) or {"offset": 0, "inode": st.st_ino}
        offset = cur.get("offset", 0)
        if cur.get("inode") != st.st_ino or st.st_size < offset:
            log.info("source %s rotated/truncated - restarting from 0", name)
            offset = 0
        if st.st_size == offset:
            self.source_status[name] = {"path": path, "state": "ok", "offset": offset, "size": st.st_size, "at": utcnow()}
            return 0
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(READ_CHUNK)
        parts = data.split(b"\n")
        tail = parts.pop()  # incomplete last line (or b"" when data ends with newline)
        consumed = len(data) - len(tail)
        if tail and len(tail) > MAX_LINE:
            self._quarantine(name, offset + consumed, "oversized record (> 64 KiB, no newline)", tail[:300])
            consumed = len(data)
        pos = offset
        count = 0
        for raw in parts:
            line_offset = pos
            pos += len(raw) + 1
            if not raw.strip():
                continue
            if len(raw) > MAX_LINE:
                self._quarantine(name, line_offset, f"oversized record ({len(raw)} bytes)", raw[:300])
                continue
            count += self._ingest_line(name, path, line_offset, raw)
        self.db.ingest_cursors.update_one(
            {"_id": name},
            {"$set": {"offset": offset + consumed, "inode": st.st_ino, "path": path, "updated_at": utcnow()}},
            upsert=True,
        )
        self.source_status[name] = {"path": path, "state": "ok", "offset": offset + consumed, "size": st.st_size, "at": utcnow()}
        return count

    def _quarantine(self, source, offset, reason, sample: bytes):
        self.stats["parse_errors"] += 1
        self.db.ingest_errors.insert_one({
            "source": source, "offset": offset, "reason": reason[:300],
            "sample": sample.decode("utf-8", "replace")[:300], "at": utcnow(),
        })

    def _ingest_line(self, source, path, offset, raw: bytes, extra_tags=()) -> int:
        line = raw.decode("utf-8", "replace")
        try:
            ev = PARSERS[source](line)
        except ParseError as exc:
            # store only a sanitized sample of the bad record
            try:
                sample = json.dumps(redact.sanitize(json.loads(line)))[:300]
            except Exception:
                sample = line[:300]
            self._quarantine(source, offset, str(exc), sample.encode())
            return 0
        except Exception as exc:  # parser bug: contain it, count it, carry on
            self._quarantine(source, offset, f"parser exception: {type(exc).__name__}", line[:300].encode())
            return 0

        if HEALTH_PROBE_SOURCE_IP and ev.get("src_ip") == HEALTH_PROBE_SOURCE_IP:
            self.stats["probe_filtered"] += 1
            return 0

        event_id = str(uuid.uuid5(EVENT_NS, f"{source}:{hashlib.sha256(raw).hexdigest()}"))
        now = utcnow()
        decoy = self.decoys_by_source.get(ev["source_type"])
        ev.update({
            "_id": event_id,
            "event_id": event_id,
            "ingested_at": now,
            "decoy_id": decoy["_id"] if decoy else None,
            "raw_ref": f"raw_events/{event_id}",
        })
        if ev.get("dst_port") is not None:
            ev["dst_endpoint"] = f"{ev.get('dst_ip') or decoy and decoy.get('address') or '?'}:{ev['dst_port']}"
        ev["approved_source"] = bool(ev.get("src_ip") and ev["src_ip"] in self.approved)
        ev["tags"] = self.tagger.tag(ev)
        if ev["approved_source"]:
            ev["tags"] = sorted(set(ev["tags"]) | {"approved_test_source"})
        if ev.get("parser_status") == "partial":
            ev["tags"] = sorted(set(ev["tags"]) | {"partial_record"})
        if extra_tags:
            ev["tags"] = sorted(set(ev["tags"]) | set(extra_tags))
        try:
            self.db.events.insert_one(ev)
        except DuplicateKeyError:
            self.stats["duplicates"] += 1
            return 0
        try:
            raw_obj = json.loads(line)
        except Exception:
            raw_obj = {"unparsed": line[:1000]}
        self.db.raw_events.insert_one({"_id": event_id, "source_type": source, "source_file": path,
                                       "offset": offset, "raw": redact.sanitize(raw_obj), "stored_at": now})
        self.stats["events_ingested"] += 1
        self.last_event_at = ev["event_time"]
        touched = self.engine.evaluate(ev)
        self.stats["alerts_touched"] += len(touched)
        return 1

    # ---- synthetic monitoring events (health) go through the same pipeline
    def emit_internal(self, decoy_id, category, outcome, message):
        now = utcnow()
        ev = {
            "_id": str(uuid.uuid4()), "source_type": "collector", "sensor_id": "collector", "event_time": now,
            "ingested_at": now, "decoy_id": decoy_id, "src_ip": None, "src_port": None, "dst_ip": None,
            "dst_port": None, "service": "health", "protocol": None, "event_category": category,
            "outcome": outcome, "session_id": None, "message": message, "tags": ["monitoring"],
            "parser_status": "parsed", "raw_ref": None, "approved_source": False,
        }
        ev["event_id"] = ev["_id"]
        self.db.events.insert_one(ev)
        self.engine.evaluate(ev)

    # ---- health
    def _probe(self, host, port, timeout=2.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if HEALTH_PROBE_BIND_IP:
                s.bind((HEALTH_PROBE_BIND_IP, 0))
            s.connect((host, int(port)))
            s.close()
            return True, "ok"
        except OSError as exc:
            return False, exc.strerror or type(exc).__name__

    def health_checks(self, force_ids=()):
        now = utcnow()
        for d in self.db.decoys.find({}):
            did = d["_id"]
            requested = aware(d.get("health_check_requested_at"))
            last = aware((d.get("health") or {}).get("checked_at"))
            forced = did in force_ids or (requested and (last is None or requested > last))
            if not forced and time.time() - self._last_health < HEALTH_SECONDS:
                continue
            if not d.get("enabled"):
                self.db.decoys.update_one({"_id": did}, {"$set": {"health": {
                    "status": "disabled", "checked_at": now, "targets": [], "consecutive_failures": 0,
                    "detail": "decoy disabled - not probed"}}})
                self.health_state.pop(did, None)
                continue
            targets = []
            for port in d.get("health_ports") or d.get("ports") or []:
                ok, detail = self._probe(d.get("address"), port)
                targets.append({"port": port, "ok": ok, "detail": detail})
            ok_count = sum(1 for t in targets if t["ok"])
            status = "healthy" if targets and ok_count == len(targets) else ("degraded" if ok_count else "unhealthy")
            detail = f"{ok_count}/{len(targets)} health ports answering"
            # log freshness: the HTTP decoy writes a heartbeat; others are judged on ports only
            if d.get("source_type") == "http_decoy":
                hb = self.db.events.find_one({"decoy_id": did, "event_category": "heartbeat"}, sort=[("event_time", -1)],
                                             projection={"event_time": 1})
                if not hb or (now - aware(hb["event_time"])).total_seconds() > HEARTBEAT_STALE_SECONDS:
                    if status == "healthy":
                        status = "degraded"
                    detail += "; heartbeat stale"
            st = self.health_state.setdefault(did, {"fails": 0, "alerted": False})
            st["fails"] = 0 if status == "healthy" else st["fails"] + 1
            if st["fails"] >= HEALTH_FAILS_BEFORE_ALERT and not st["alerted"]:
                st["alerted"] = True
                self.emit_internal(did, "health", "failed", f"Decoy {did} {status}: {detail} ({st['fails']} consecutive checks)")
            elif status == "healthy" and st["alerted"]:
                st["alerted"] = False
                self.emit_internal(did, "health", "ok", f"Decoy {did} recovered: {detail}")
            last_ev = self.db.events.find_one({"decoy_id": did, "event_category": {"$nin": ["heartbeat", "health", "egress_attempt", "sensor_status"]}},
                                              sort=[("event_time", -1)], projection={"event_time": 1})
            egress = list(self.db.events.find({"decoy_id": did, "event_category": "egress_attempt"},
                                              {"event_time": 1, "outcome": 1, "egress_target": 1}).sort("event_time", -1).limit(12))
            update = {"health": {"status": status, "checked_at": now, "targets": targets,
                                 "consecutive_failures": st["fails"], "detail": detail},
                      "last_event_at": last_ev["event_time"] if last_ev else None}
            if egress:
                latest = aware(egress[0]["event_time"])
                batch = [e for e in egress if (latest - aware(e["event_time"])).total_seconds() < 60]
                update["isolation"] = {
                    "checked_at": latest,
                    "all_blocked": all(e.get("outcome") == "blocked" for e in batch),
                    "results": [{"target": e.get("egress_target"), "outcome": e.get("outcome")} for e in batch],
                }
            self.db.decoys.update_one({"_id": did}, {"$set": update})
        if not force_ids:
            self._last_health = time.time()

    # ---- heartbeat / retention
    def heartbeat(self):
        self.db.system_status.replace_one({"_id": "collector"}, {
            "_id": "collector", "heartbeat_at": utcnow(), "last_event_at": self.last_event_at,
            "stats": self.stats, "sources": self.source_status, "rules_loaded": len(self.engine.rules),
            "indicators_loaded": len(self.engine.indicators), "approved_sources": sorted(self.approved),
            "version": "1.0.0",
        }, upsert=True)

    def retention(self):
        cfg = self.db.settings.find_one({"_id": "retention"}) or {}
        ev_days = int(cfg.get("events_days", 30))
        al_days = int(cfg.get("alerts_days", 90))
        now = utcnow()
        e_cut = now - timedelta(days=ev_days)
        a_cut = now - timedelta(days=al_days)
        r1 = self.db.events.delete_many({"event_time": {"$lt": e_cut}})
        self.db.raw_events.delete_many({"stored_at": {"$lt": e_cut}})
        self.db.ingest_errors.delete_many({"at": {"$lt": e_cut}})
        r2 = self.db.alerts.delete_many({"status": {"$in": ["Resolved", "False Positive"]}, "updated_at": {"$lt": a_cut}})
        self.db.audit_log.delete_many({"at": {"$lt": a_cut}})
        if r1.deleted_count or r2.deleted_count:
            log.info("retention: removed %d events, %d closed alerts", r1.deleted_count, r2.deleted_count)
        self.db.settings.update_one({"_id": "retention"}, {"$set": {"last_run_at": now}}, upsert=True)

    # ---- main loop
    def run(self):
        log.info("collector started; sources=%s", self.sources)
        self.refresh(force=True)
        while True:
            try:
                self.refresh()
                n = self.poll_sources()
                self.health_checks()
                if time.time() - self._last_heartbeat >= 5:
                    self.heartbeat()
                    self._last_heartbeat = time.time()
                if time.time() - self._last_retention >= 3600:
                    self.retention()
                    self._last_retention = time.time()
                if n == 0:
                    time.sleep(POLL_SECONDS)
            except PyMongoError as exc:
                log.error("database error: %s - retrying in 3s", exc)
                time.sleep(3)


def main():
    ap = argparse.ArgumentParser(description="HLPA-DS collector and detection worker")
    ap.add_argument("--reseed-rules", action="store_true", help="overwrite DB rules with rules.yml and exit")
    args = ap.parse_args()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    db = connect()
    ensure_indexes(db)
    seed_rules(db, reseed=args.reseed_rules)
    if args.reseed_rules:
        log.info("rules re-seeded from %s", RULES_FILE)
        return
    seed_indicators(db)
    Collector(db).run()


if __name__ == "__main__":
    main()
