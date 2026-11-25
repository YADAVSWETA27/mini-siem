"""Glue: ingest log files into storage, run detection, persist alerts."""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, Optional

from .models import Alert
from .parsers import PARSERS
from .rules import run_detection
from .storage import Storage
from .tail import NewLine


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


def ingest_lines(store: Storage, lines: Iterable[NewLine], source: str, path: str,
                 year: Optional[int] = None) -> IngestResult:
    """Parse lines handed over by a ``FileTailer`` and store the events (live mode).

    Each event's id is built from the file, the line's *position* in it and the line text.
    So the same line seen twice (for example after the watcher restarts and re-reads the
    file) is stored once, while two genuinely identical lines at different positions are
    both kept.
    """
    if source not in PARSERS:
        raise ValueError(f"unknown source '{source}' (choose from {', '.join(PARSERS)})")
    parser = PARSERS[source]
    where = os.path.abspath(path)
    events, skipped = [], 0
    for nl in lines:
        ev = parser(nl.text, year=year) if source == "auth" else parser(nl.text)
        if ev is None:
            skipped += 1
            continue
        ev.uid = hashlib.sha1(f"{source}|{where}|{nl.offset}|{nl.text}".encode()).hexdigest()
        events.append(ev)
    return IngestResult(parsed=len(events), skipped=skipped, new=store.insert_events(events))


def load_blocklist(path: Optional[str]) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def detect(store: Storage, cfg: Optional[dict] = None) -> tuple[int, int]:
    """Run all rules over ALL stored events. Returns (alerts found, alerts that were new).

    Alerts that already exist but have grown (more events) are updated in place."""
    alerts = run_detection(store.fetch_events(), cfg)
    new, _updated = store.upsert_alerts(alerts)
    return len(alerts), len(new)


@dataclass
class DetectResult:
    found: int                                   # alerts the rules produced on this pass
    new: list[Alert] = field(default_factory=list)      # alerts we had never stored before
    updated: list[Alert] = field(default_factory=list)  # existing alerts that grew or changed


def detect_recent(store: Storage, cfg: Optional[dict] = None, lookback_s: int = 24 * 3600) -> DetectResult:
    """Live-mode detection: run the rules over only the most recent events.

    "Recent" is measured back from the *newest event in the database*, not from the clock,
    so it also works when you replay an old log file. Re-checking a window instead of
    everything keeps each pass fast as the database grows.

    Limit: an attack that lasts longer than ``lookback_s`` can lose its beginning from the
    window, so keep the lookback comfortably larger than the longest attack you care about.
    """
    newest = store.newest_event_time()
    if newest is None:
        return DetectResult(found=0)
    alerts = run_detection(store.fetch_events(since=newest - timedelta(seconds=lookback_s)), cfg)
    new, updated = store.upsert_alerts(alerts)
    return DetectResult(found=len(alerts), new=new, updated=updated)
