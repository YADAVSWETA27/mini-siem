"""Glue: ingest log files into storage, run detection, persist alerts."""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from .parsers import PARSERS
from .rules import run_detection
from .storage import Storage


@dataclass
class IngestResult:
    parsed: int   # lines turned into events
    skipped: int  # lines no parser understood (noise, unsupported formats)
    new: int      # events not already in the database


def ingest_file(store: Storage, path: str, source: str, year: Optional[int] = None) -> IngestResult:
    """Parse ``path`` with the ``source`` parser and store the events.

    Re-ingesting the same file is safe (idempotent): identical lines get a stable id made of
    the line plus its occurrence number, so true duplicates are kept but re-runs add nothing.
    """
    if source not in PARSERS:
        raise ValueError(f"unknown source '{source}' (choose from {', '.join(PARSERS)})")
    parser = PARSERS[source]
    events, skipped, seen = [], 0, Counter()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            ev = parser(line, year=year) if source == "auth" else parser(line)
            if ev is None:
                skipped += 1
                continue
            seen[line] += 1
            ev.uid = hashlib.sha1(f"{source}|{line}|{seen[line]}".encode()).hexdigest()
            events.append(ev)
    return IngestResult(parsed=len(events), skipped=skipped, new=store.insert_events(events))


def load_blocklist(path: Optional[str]) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def detect(store: Storage, cfg: Optional[dict] = None) -> tuple[int, int]:
    """Run all rules over stored events. Returns (alerts found, alerts that were new)."""
    alerts = run_detection(store.fetch_events(), cfg)
    return len(alerts), store.insert_alerts(alerts)
