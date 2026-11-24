"""SQLite persistence for events and alerts."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Optional

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT UNIQUE NOT NULL,
    timestamp  TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip     TEXT,
    username   TEXT,
    host       TEXT,
    message    TEXT,
    raw        TEXT,
    extra      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key   TEXT UNIQUE NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    src_ip      TEXT,
    username    TEXT,
    description TEXT,
    mitre       TEXT,
    event_count INTEGER,
    evidence    TEXT,
    created_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
"""


class Storage:
    def __init__(self, path: str = "siem.db"):
        self.path = str(path)
        # Streamlit runs scripts on worker threads, hence check_same_thread=False.
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ---------------------------------------------------------------- events
    def insert_events(self, events: Iterable[Event]) -> int:
        """Insert events, silently skipping ones already stored. Returns #new rows."""
        rows = []
        for e in events:
            uid = e.uid or hashlib.sha1(f"{e.source}|{e.raw}".encode()).hexdigest()
            rows.append((
                uid, e.timestamp.isoformat(), e.source, e.event_type, e.src_ip,
                e.username, e.host, e.message, e.raw, json.dumps(e.extra),
            ))
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO events (event_hash, timestamp, source, event_type, src_ip,"
            " username, host, message, raw, extra) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self.conn.commit()
        return self.conn.total_changes - before

    def fetch_events(self, since: Optional[datetime] = None) -> list[Event]:
        sql, params = "SELECT * FROM events", ()
        if since:
            sql, params = sql + " WHERE timestamp >= ?", (since.isoformat(),)
        sql += " ORDER BY timestamp"
        return [
            Event(
                timestamp=datetime.fromisoformat(r["timestamp"]), source=r["source"],
                event_type=r["event_type"], src_ip=r["src_ip"], username=r["username"],
                host=r["host"], message=r["message"] or "", raw=r["raw"] or "",
                extra=json.loads(r["extra"] or "{}"), uid=r["event_hash"],
            )
            for r in self.conn.execute(sql, params)
        ]

    # ---------------------------------------------------------------- alerts
    def insert_alerts(self, alerts: Iterable[Alert]) -> int:
        now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        rows = [
            (a.dedup_key, a.rule_id, a.title, a.severity, a.timestamp.isoformat(), a.src_ip,
             a.username, a.description, a.mitre, a.event_count, json.dumps(a.evidence), now)
            for a in alerts
        ]
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO alerts (dedup_key, rule_id, title, severity, timestamp, src_ip,"
            " username, description, mitre, event_count, evidence, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self.conn.commit()
        return self.conn.total_changes - before

    def fetch_alerts(self) -> list[dict]:
        out = []
        for r in self.conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC"):
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    # --------------------------------------------------------------- helpers
    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def counts(self) -> dict:
        return {
            "events": self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "alerts": self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        }

    def reset(self) -> None:
        self.conn.execute("DELETE FROM events")
        self.conn.execute("DELETE FROM alerts")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
