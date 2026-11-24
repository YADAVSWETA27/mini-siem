"""Normalized data model shared by every parser, rule and the dashboard.

Whatever the original log format was (syslog, nginx access log, JSON), it is
converted into an ``Event``. Detection rules only ever see ``Event`` objects,
which is what makes it easy to add a new log source without touching the rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SEVERITIES = ["low", "medium", "high", "critical"]


@dataclass
class Event:
    timestamp: datetime  # always naive UTC
    source: str  # auth | web | app
    event_type: str  # auth_failure | auth_success | http_request | privilege_cmd | app_*
    src_ip: Optional[str] = None
    username: Optional[str] = None
    host: Optional[str] = None
    message: str = ""
    raw: str = ""  # original log line, kept as evidence
    extra: dict = field(default_factory=dict)  # source-specific fields (path, status, ...)
    uid: str = ""  # stable hash used for de-duplication on re-ingest


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str  # low | medium | high | critical
    timestamp: datetime
    description: str
    src_ip: Optional[str] = None
    username: Optional[str] = None
    mitre: str = ""  # MITRE ATT&CK technique id(s)
    event_count: int = 1
    evidence: list = field(default_factory=list)  # raw log lines / constituent alerts
    dedup_key: str = ""  # makes re-running detection idempotent
