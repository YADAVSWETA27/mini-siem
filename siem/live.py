"""Live monitoring: watch log files, save new events, run detection, report alert changes.

One call to ``LiveMonitor.step()`` is one round of:

    check every watched file -> save the new lines -> (if anything arrived) run detection
    on the recent window -> report which alerts are new and which grew

The command line (`python cli.py watch`) simply calls ``step()`` once a second. Keeping the
logic here, separate from the loop and the printing, means tests can drive it directly
without waiting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .engine import detect_recent, ingest_lines
from .models import Alert
from .parsers import PARSERS
from .storage import Storage
from .tail import FileTailer


@dataclass
class StepResult:
    new_events: int = 0   # events saved during this round
    skipped: int = 0      # lines nothing could parse
    new_alerts: list[Alert] = field(default_factory=list)
    updated_alerts: list[Alert] = field(default_factory=list)


class LiveMonitor:
    def __init__(self, store: Storage, watch: Iterable[tuple[str, str]], cfg: Optional[dict] = None,
                 from_start: bool = False, lookback_s: int = 24 * 3600, year: Optional[int] = None):
        """``watch`` is a list of ``(source, path)`` pairs, e.g. ``[("auth", "live/auth.log")]``."""
        self.store, self.cfg, self.lookback_s, self.year = store, cfg, lookback_s, year
        self.watching: list[tuple[str, str, FileTailer]] = []
        for source, path in watch:
            if source not in PARSERS:
                raise ValueError(f"unknown source '{source}' (choose from {', '.join(PARSERS)})")
            self.watching.append((source, path, FileTailer(path, from_start=from_start)))
        self._first_round = True

    def step(self) -> StepResult:
        result = StepResult()
        for source, path, tailer in self.watching:
            lines = tailer.poll()
            if not lines:
                continue
            saved = ingest_lines(self.store, lines, source, path, year=self.year)
            result.new_events += saved.new
            result.skipped += saved.skipped

        # Detection only runs when something new arrived (the rules depend on event times,
        # not on the clock, so re-running with nothing new could not find anything new).
        # The very first round always runs it, in case an earlier session stopped after saving
        # events but before checking them.
        if result.new_events or self._first_round:
            found = detect_recent(self.store, self.cfg, self.lookback_s)
            result.new_alerts, result.updated_alerts = found.new, found.updated
        self._first_round = False
        return result
