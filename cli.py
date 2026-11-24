#!/usr/bin/env python3
"""Mini-SIEM command line.

  python cli.py demo                      generate sample logs, ingest them, run detection
  python cli.py ingest --source web --file access.log
  python cli.py detect [--blocklist data/blocklist.txt]
  python cli.py alerts [--min-severity high]
  python cli.py rules
  python cli.py reset
"""
from __future__ import annotations

import argparse
import os
import sys

from siem import sample_data
from siem.engine import detect, ingest_file, load_blocklist
from siem.models import SEVERITIES
from siem.rules import all_rules
from siem.storage import Storage

DEFAULT_DB = os.environ.get("SIEM_DB", "siem.db")
SAMPLE_DIR = os.path.join("data", "sample")


def _print_alerts(alerts: list[dict]) -> None:
    if not alerts:
        print("No alerts.")
        return
    print(f"{'TIME (UTC)':<19} {'SEV':<9} {'RULE':<9} {'SOURCE IP':<16} {'USER':<10} TITLE")
    print("-" * 100)
    for a in alerts:
        print(f"{a['timestamp'][:19].replace('T', ' '):<19} {a['severity'].upper():<9} {a['rule_id']:<9} "
              f"{(a['src_ip'] or '-'):<16} {(a['username'] or '-'):<10} {a['title']}")


def cmd_demo(args, store: Storage) -> int:
    if not args.keep:
        store.reset()
    files = sample_data.generate(SAMPLE_DIR)
    print(f"Generated sample logs in {SAMPLE_DIR}/")
    for src, path in (("auth", files.auth), ("web", files.web), ("app", files.app)):
        r = ingest_file(store, path, src, year=files.year)
        print(f"  ingested {src:<4} {r.parsed:>4} events ({r.skipped} skipped, {r.new} new)")
    found, new = detect(store, {"blocklist": load_blocklist(files.blocklist)})
    print(f"Detection complete: {found} alerts ({new} new)\n")
    _print_alerts(store.fetch_alerts()[::-1])
    print(f"\nOpen the dashboard with:  streamlit run dashboard.py   (database: {store.path})")
    return 0


def cmd_ingest(args, store: Storage) -> int:
    r = ingest_file(store, args.file, args.source, year=args.year)
    print(f"{args.file}: {r.parsed} events parsed, {r.skipped} lines skipped, {r.new} new")
    return 0


def cmd_detect(args, store: Storage) -> int:
    found, new = detect(store, {"blocklist": load_blocklist(args.blocklist)})
    print(f"{found} alerts found ({new} new)")
    return 0


def cmd_alerts(args, store: Storage) -> int:
    floor = SEVERITIES.index(args.min_severity)
    _print_alerts([a for a in store.fetch_alerts()[::-1] if SEVERITIES.index(a["severity"]) >= floor])
    return 0


def cmd_rules(args, store: Storage) -> int:
    for r in all_rules():
        print(f"{r.id:<9} {r.severity:<9} {r.mitre or '-':<18} {r.title}")
    return 0


def cmd_reset(args, store: Storage) -> int:
    store.reset()
    print("Database cleared.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Mini-SIEM")
    p.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="generate sample logs, ingest and detect")
    d.add_argument("--keep", action="store_true", help="don't clear the database first")
    d.set_defaults(fn=cmd_demo)

    i = sub.add_parser("ingest", help="parse a log file into the database")
    i.add_argument("--source", required=True, choices=["auth", "web", "app"])
    i.add_argument("--file", required=True)
    i.add_argument("--year", type=int, help="year for syslog timestamps (auth logs only)")
    i.set_defaults(fn=cmd_ingest)

    t = sub.add_parser("detect", help="run all detection rules")
    t.add_argument("--blocklist", help="file with one known-bad IP per line")
    t.set_defaults(fn=cmd_detect)

    a = sub.add_parser("alerts", help="print alerts")
    a.add_argument("--min-severity", default="low", choices=SEVERITIES)
    a.set_defaults(fn=cmd_alerts)

    sub.add_parser("rules", help="list detection rules").set_defaults(fn=cmd_rules)
    sub.add_parser("reset", help="delete all events and alerts").set_defaults(fn=cmd_reset)

    args = p.parse_args(argv)
    return args.fn(args, Storage(args.db))


if __name__ == "__main__":
    sys.exit(main())
