#!/usr/bin/env python3
"""Mini-SIEM command line.

  python cli.py demo                      generate sample logs, ingest them, run detection
  python cli.py ingest --source web --file access.log
  python cli.py detect [--blocklist data/blocklist.txt]
  python cli.py alerts [--min-severity high]
  python cli.py rules
  python cli.py reset

Live monitoring (start `watch` first, then `simulate` in a second window):
  python cli.py watch --auth live-logs/auth.log --web live-logs/access.log
  python cli.py simulate [--scenario multistage|spray] [--delay 1.0]
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone

from siem import sample_data
from siem.engine import detect, ingest_file, load_blocklist
from siem.live import LiveMonitor, StepResult
from siem.models import SEVERITIES
from siem.rules import all_rules
from siem.simulator import FILENAMES, SCENARIOS, files_used, simulate
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


def _print_live(res: StepResult) -> None:
    clock = datetime.now(timezone.utc).strftime("%H:%M:%S")
    if res.new_events:
        print(f"{clock}  +{res.new_events} event(s)")
    for label, alerts in (("NEW", res.new_alerts), ("UPDATED", res.updated_alerts)):
        for a in sorted(alerts, key=lambda x: x.timestamp):
            print(f"{clock}  {label:<8} {a.severity.upper():<9} {a.rule_id:<9} "
                  f"{(a.src_ip or a.username or '-'):<15} {a.title} ({a.event_count} events)")
            if label == "NEW":
                print(f"{'':10} {a.description[:110]}")
    sys.stdout.flush()


def cmd_watch(args, store: Storage) -> int:
    watch = ([("auth", p) for p in args.auth] + [("web", p) for p in args.web]
             + [("app", p) for p in args.app])
    if not watch:
        print("Nothing to watch. Give at least one of --auth, --web or --app (each takes a file path).")
        return 2
    monitor = LiveMonitor(
        store, watch, cfg={"blocklist": load_blocklist(args.blocklist)},
        from_start=args.from_start, lookback_s=int(args.lookback_hours * 3600), year=args.year)

    print("Live monitoring. Watching:")
    for source, path in watch:
        print(f"  {source:<5} {path}")
    print(f"Saving to {store.path}. Open the dashboard in another window with: streamlit run dashboard.py")
    print("Files that do not exist yet are picked up as soon as they are created. Press Ctrl+C to stop.\n")

    new_total = updated_total = events_total = rounds = 0
    try:
        while True:
            res = monitor.step()
            _print_live(res)
            events_total += res.new_events
            new_total += len(res.new_alerts)
            updated_total += len(res.updated_alerts)
            rounds += 1
            if args.max_steps and rounds >= args.max_steps:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    print(f"Stopped. This session: {events_total} event(s) saved, {new_total} new alert(s), "
          f"{updated_total} alert update(s).")
    return 0


def cmd_simulate(args, store) -> int:
    used = files_used(args.scenario)
    paths = {key: os.path.join(args.dir, FILENAMES[key]) for key in used}
    flags = " ".join(f"--{key} {path}" for key, path in paths.items())
    print(f"Simulating a FAKE '{args.scenario}' attack into {args.dir}{os.sep} "
          f"(one log line every {args.delay}s).")
    print(f"Watch it from another window with:\n  python cli.py watch {flags}\n")
    simulate(args.dir, args.scenario, args.delay,
             on_write=lambda key, line: print(f"[{key}] {line[:105]}", flush=True))
    print("\nSimulation finished.")
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

    w = sub.add_parser("watch", help="live monitoring: watch log files and print alerts as they happen")
    w.add_argument("--auth", action="append", default=[], metavar="FILE", help="auth.log file to watch (repeatable)")
    w.add_argument("--web", action="append", default=[], metavar="FILE", help="web access log to watch (repeatable)")
    w.add_argument("--app", action="append", default=[], metavar="FILE", help="JSON app log to watch (repeatable)")
    w.add_argument("--blocklist", help="file with one known-bad IP per line")
    w.add_argument("--from-start", action="store_true",
                   help="also process lines already in the files (default: only new lines)")
    w.add_argument("--interval", type=float, default=1.0, help="seconds between checks (default 1)")
    w.add_argument("--lookback-hours", type=float, default=24, help="how far back each check looks (default 24)")
    w.add_argument("--year", type=int, help="year for syslog timestamps (auth logs only; default: infer)")
    w.add_argument("--max-steps", type=int, default=0, help=argparse.SUPPRESS)  # for scripts and tests
    w.set_defaults(fn=cmd_watch)

    s = sub.add_parser("simulate", help="write a FAKE attack slowly into live log files (for demos)")
    s.add_argument("--dir", default="live-logs", help="folder for the fake log files (default: live-logs)")
    s.add_argument("--scenario", choices=SCENARIOS, default="multistage")
    s.add_argument("--delay", type=float, default=1.0, help="seconds between log lines (default 1)")
    s.set_defaults(fn=cmd_simulate)

    args = p.parse_args(argv)
    store = None if args.cmd == "simulate" else Storage(args.db)  # the simulator needs no database
    return args.fn(args, store)


if __name__ == "__main__":
    sys.exit(main())
