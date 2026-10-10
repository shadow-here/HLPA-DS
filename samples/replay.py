#!/usr/bin/env python3
"""
Replay synthetic sample logs into the running HLPA-DS pipeline.

It appends the generated sample records (see generate_samples.py) to the live
decoy log files that the collector tails. The collector then parses, stores and
evaluates them exactly as it would real sensor output - so the dashboard fills
with events and alerts for a demo or an automated test. No network traffic and
no service interaction is involved; this only writes log lines.

Usage (inside Docker):
    docker compose run --rm replay            # generate + replay everything
    docker compose run --rm replay --speed 5  # 5x faster inter-record pacing

Usage (native dev): point the *_LOG env vars at the files the collector tails.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
GEN = os.path.join(HERE, "generated")

TARGETS = {
    "cowrie.json": os.environ.get("COWRIE_LOG", "/logs/cowrie/cowrie.json"),
    "opencanary.log": os.environ.get("OPENCANARY_LOG", "/logs/opencanary/opencanary.log"),
    "http_decoy.json": os.environ.get("HTTP_LOG", "/logs/http/http_decoy.json"),
}


def ensure_samples(regen: bool):
    if regen or not os.path.exists(os.path.join(GEN, "MANIFEST.json")):
        subprocess.run([sys.executable, os.path.join(HERE, "generate_samples.py"), "--out", GEN], check=True)


def append_line(path, line):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    new = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line if line.endswith("\n") else line + "\n")
        fh.flush()
    if new:
        try:  # let the (non-root) decoy processes keep appending to this file
            os.chmod(path, 0o666)
        except OSError:
            pass


def replay(speed: float):
    # Merge all records on their timestamp so cross-sensor ordering is realistic.
    streams = []
    for name, target in TARGETS.items():
        src = os.path.join(GEN, name)
        if not os.path.exists(src):
            continue
        with open(src, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                ts = rec.get("timestamp") or rec.get("utc_time") or rec.get("ts") or ""
                streams.append((ts, target, line))
    streams.sort(key=lambda x: x[0])
    total = len(streams)
    print(f"[replay] writing {total} synthetic records (speed {speed}x) ...", flush=True)
    written = 0
    for i, (_, target, line) in enumerate(streams):
        append_line(target, line)
        written += 1
        if i + 1 < total and speed > 0:
            time.sleep(min(0.05 / speed, 0.05))
    print(f"[replay] done: {written} records written. Watch the dashboard for new events and alerts.", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Replay synthetic sample logs into the pipeline")
    ap.add_argument("--speed", type=float, default=1.0, help="pacing multiplier (higher = faster)")
    ap.add_argument("--regen", action="store_true", help="regenerate sample logs first")
    ap.add_argument("--fresh-times", action="store_true", help="regenerate with base-time = now-5m so events land in the default 24h view")
    args = ap.parse_args()
    if args.fresh_times:
        from datetime import datetime, timedelta, timezone
        base = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        subprocess.run([sys.executable, os.path.join(HERE, "generate_samples.py"), "--out", GEN, "--base-time", base], check=True)
    else:
        ensure_samples(args.regen)
    replay(args.speed)


if __name__ == "__main__":
    main()
