"""Deterministic, explainable rule engine (PRD 3.2 / 4.4).

Every rule decision is reproducible from stored events: the engine queries the
event store for the rule's time window rather than relying on hidden state, so
a restarted worker makes the same decisions.
"""
from __future__ import annotations

import logging
import re
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone


log = logging.getLogger("hlpa.engine")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
OPEN_STATES = ["New", "Acknowledged", "Investigating", "Contained (lab only)"]
MAX_EVIDENCE_EVENTS = 1000


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime) -> datetime:
    """Mongo returns naive UTC datetimes unless tz_aware is set; normalise."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def max_sev(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


# --------------------------------------------------------------------------- taggers

class Tagger:
    def __init__(self, cfg: list[dict]):
        self.items = []
        for t in cfg or []:
            compiled = [(g["tag"], [re.compile(p, re.I) for p in g["patterns"]]) for g in t.get("tags", [])]
            self.items.append((t["field"], t.get("normalize", "lower"), compiled))

    @staticmethod
    def _norm(value: str, mode: str) -> str:
        v = value
        if mode == "url":
            # decode repeatedly (double encoding) and normalise case/slashes
            for _ in range(3):
                nv = urllib.parse.unquote_plus(v)
                if nv == v:
                    break
                v = nv
            v = v.replace("\\", "/")
        return v.lower()

    def tag(self, ev: dict) -> list[str]:
        tags = set(ev.get("tags") or [])
        for field, mode, groups in self.items:
            val = ev.get(field)
            if not val or not isinstance(val, str):
                continue
            norm = self._norm(val, mode)
            for tag, pats in groups:
                if any(p.search(norm) for p in pats):
                    tags.add(tag)
        return sorted(tags)


# --------------------------------------------------------------------------- filters

def event_matches_filter(ev: dict, flt: dict) -> bool:
    for key, allowed in (flt or {}).items():
        if key == "exclude":
            for ek, banned in allowed.items():
                if ev.get(ek) in banned:
                    return False
            continue
        val = ev.get(key)
        if isinstance(val, list):
            if not set(val) & set(allowed):
                return False
        elif val not in allowed:
            return False
    return True


def filter_to_query(flt: dict) -> dict:
    q: dict = {}
    for key, allowed in (flt or {}).items():
        if key == "exclude":
            for ek, banned in allowed.items():
                q[ek] = {"$nin": list(banned)}
        else:
            q[key] = {"$in": list(allowed)}
    return q


def render(template: str, ev: dict) -> str:
    def rep(m):
        v = ev.get(m.group(1))
        return str(v) if v not in (None, "") else "unknown"
    return re.sub(r"\{(\w+)\}", rep, template or "")


# --------------------------------------------------------------------------- engine

class RuleEngine:
    def __init__(self, db):
        self.db = db
        self.rules: list[dict] = []
        self.indicators: set[str] = set()

    def load(self, rules: list[dict], indicators: set[str]):
        self.rules = [r for r in rules if r.get("enabled", True)]
        self.indicators = indicators

    # ---- public
    def evaluate(self, ev: dict) -> list[str]:
        """Evaluate one freshly stored event. Returns alert ids created/updated."""
        touched = []
        for rule in self.rules:
            try:
                aid = self._evaluate_rule(rule, ev)
                if aid:
                    touched.append(aid)
            except Exception:  # a broken rule must never stop ingestion
                log.exception("rule %s failed on event %s", rule.get("id"), ev.get("_id"))
        return touched

    # ---- internals
    def _evaluate_rule(self, rule: dict, ev: dict):
        kind = rule.get("kind", "attacker")
        if kind == "attacker" and ev.get("approved_source"):
            return None
        rtype = rule.get("type")
        if rtype != "ioc" and not event_matches_filter(ev, rule.get("filter")):
            return None
        group_by = rule.get("group_by") or []
        group = {f: ev.get(f) for f in group_by}
        if any(v in (None, "") for v in group.values()):
            return None  # cannot group without the field; never invent values

        t = aware(ev["event_time"])
        if rtype in ("threshold", "distinct"):
            window = int(rule.get("window_seconds", 60))
            q = filter_to_query(rule.get("filter"))
            q.update(group)
            q["event_time"] = {"$gte": t - timedelta(seconds=window), "$lte": t}
            q["approved_source"] = {"$ne": True}
            fields = {"_id": 1, "event_time": 1}
            for f in rule.get("evidence_fields", []):
                fields[f] = 1
            if rule.get("distinct_field"):
                fields[rule["distinct_field"]] = 1
            docs = list(self.db.events.find(q, fields).sort("event_time", 1).limit(MAX_EVIDENCE_EVENTS))
            if rtype == "threshold":
                observed = len(docs)
            else:
                df = rule["distinct_field"]
                observed = len({d.get(df) for d in docs if d.get(df) not in (None, "")})
            if observed < int(rule.get("threshold", 1)):
                return None
            severity = rule.get("severity", "medium")
            esc = rule.get("escalate")
            if esc and observed >= int(esc.get("at", 10**9)):
                severity = max_sev(severity, esc.get("severity", severity))
            unit = f"distinct {rule['distinct_field']} values" if rtype == "distinct" else "matching events"
            evidence = {
                "condition": f"{observed} {unit} within {window}s (threshold {rule.get('threshold')})",
                "observed": observed,
                "threshold": rule.get("threshold"),
                "window_seconds": window,
                "group": group,
                "sample_fields": self._samples(docs, rule),
            }
            return self._upsert_alert(rule, ev, group, [d["_id"] for d in docs], evidence, severity, observed)

        if rtype == "match":
            severity = rule.get("severity", "medium")
            matched_tags = []
            for tag, sev in (rule.get("severity_by_tag") or {}).items():
                if tag in (ev.get("tags") or []):
                    matched_tags.append(tag)
                    severity = max_sev(severity, sev)
            evidence = {
                "condition": "single event matched rule filter" + (f" (tags: {', '.join(matched_tags)})" if matched_tags else ""),
                "group": group,
                "matched_tags": matched_tags,
                "sample_fields": self._samples([ev], rule),
            }
            return self._upsert_alert(rule, ev, group, [ev["_id"]], evidence, severity, 1)

        if rtype == "ioc":
            hits = [(f, ev.get(f)) for f in rule.get("ioc_fields", []) if ev.get(f) and str(ev.get(f)).lower() in self.indicators]
            if not hits:
                return None
            evidence = {
                "condition": "observed value is on the local indicator list (a lead, not attribution)",
                "group": group,
                "indicator_hits": [{"field": f, "value": v} for f, v in hits],
                "sample_fields": self._samples([ev], rule),
            }
            return self._upsert_alert(rule, ev, group, [ev["_id"]], evidence, rule.get("severity", "high"), 1)

        if rtype == "post_response":
            contained = self.db.alerts.find_one(
                {"src_ip": ev.get("src_ip"), "status": "Contained (lab only)", "contained_at": {"$lte": t}},
                {"_id": 1, "contained_at": 1},
            )
            if not contained:
                return None
            evidence = {
                "condition": f"source active after alert {contained['_id']} was marked Contained (lab only)",
                "group": group,
                "contained_alert": contained["_id"],
                "contained_at": aware(contained["contained_at"]).isoformat(),
                "sample_fields": self._samples([ev], rule),
            }
            return self._upsert_alert(rule, ev, group, [ev["_id"]], evidence, rule.get("severity", "medium"), 1)
        return None

    @staticmethod
    def _samples(docs, rule) -> dict:
        out = {}
        for f in rule.get("evidence_fields", []):
            vals = []
            for d in docs:
                v = d.get(f)
                if v not in (None, "") and v not in vals:
                    vals.append(v)
                if len(vals) >= 10:
                    break
            if vals:
                out[f] = vals
        return out

    def _upsert_alert(self, rule, ev, group, event_ids, evidence, severity, observed):
        t = aware(ev["event_time"])
        now = now_utc()
        group_key = "|".join(f"{k}={v}" for k, v in group.items())
        dedupe = int(rule.get("dedupe_seconds", 300))
        existing = self.db.alerts.find_one({
            "rule_id": rule["id"],
            "group_key": group_key,
            "status": {"$in": OPEN_STATES},
            "last_seen": {"$gte": t - timedelta(seconds=dedupe)},
        })
        if existing:
            known = set(existing.get("event_ids", []))
            new_ids = [i for i in event_ids if i not in known]
            if not new_ids and aware(existing["last_seen"]) >= t:
                return None
            # keep evidence from earlier matches: merge sample values and matched tags
            old_ev = existing.get("matched_evidence") or {}
            merged = dict(old_ev.get("sample_fields") or {})
            for f, vals in (evidence.get("sample_fields") or {}).items():
                cur = list(merged.get(f) or [])
                for v in vals:
                    if v not in cur and len(cur) < 10:
                        cur.append(v)
                merged[f] = cur
            evidence["sample_fields"] = merged
            if "matched_tags" in evidence:
                evidence["matched_tags"] = sorted(set(evidence["matched_tags"]) | set(old_ev.get("matched_tags") or []))
                if evidence["matched_tags"]:
                    evidence["condition"] = f"single event matched rule filter (tags seen: {', '.join(evidence['matched_tags'])})"
            room = max(0, MAX_EVIDENCE_EVENTS - len(known))
            update = {
                "$set": {
                    "last_seen": max(aware(existing["last_seen"]), t),
                    "updated_at": now,
                    "severity": max_sev(existing.get("severity", "low"), severity),
                    "matched_evidence": evidence,
                    "observed_peak": max(existing.get("observed_peak", 0), observed),
                },
                "$inc": {"event_count": len(new_ids)},
            }
            if new_ids and room:
                update["$push"] = {"event_ids": {"$each": new_ids[:room]}}
            self.db.alerts.update_one({"_id": existing["_id"]}, update)
            if new_ids:
                self.db.events.update_many({"_id": {"$in": new_ids}}, {"$addToSet": {"alert_ids": existing["_id"]}})
            return existing["_id"]

        alert_id = f"ALR-{now.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        first = self.db.events.find_one({"_id": {"$in": event_ids}}, sort=[("event_time", 1)], projection={"event_time": 1})
        first_seen = aware(first["event_time"]) if first else t
        ingested = aware(ev.get("ingested_at")) or now
        doc = {
            "_id": alert_id,
            "alert_id": alert_id,
            "rule_id": rule["id"],
            "rule_version": rule.get("version", 1),
            "rule_name": rule.get("name"),
            "kind": rule.get("kind", "attacker"),
            "title": render(rule.get("title", rule.get("name", "")), ev),
            "summary": rule.get("description", ""),
            "severity": severity,
            "status": "New",
            "group_key": group_key,
            "src_ip": ev.get("src_ip"),
            "decoy_id": ev.get("decoy_id"),
            "sensor_id": ev.get("sensor_id"),
            "service": ev.get("service"),
            "session_id": ev.get("session_id"),
            "first_seen": first_seen,
            "last_seen": t,
            "event_count": len(event_ids),
            "event_ids": event_ids[:MAX_EVIDENCE_EVENTS],
            "observed_peak": observed,
            "matched_evidence": evidence,
            "analyst_notes": [],
            "history": [{"at": now, "actor": "system", "action": "created", "to": "New",
                         "note": f"Rule {rule['id']} v{rule.get('version', 1)} matched"}],
            "notification": {"status": "not_configured"},
            "created_at": now,
            "updated_at": now,
            "detection_latency_ms": int((now - ingested).total_seconds() * 1000),
        }
        self.db.alerts.insert_one(doc)
        self.db.events.update_many({"_id": {"$in": event_ids}}, {"$addToSet": {"alert_ids": alert_id}})
        log.info("ALERT %s %s [%s] %s", alert_id, rule["id"], severity, doc["title"])
        return alert_id
