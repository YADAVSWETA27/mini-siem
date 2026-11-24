"""Log parsers. Each one turns a raw line into a normalized ``Event`` (or ``None``).

Supported sources
-----------------
auth : Linux syslog-style auth.log (sshd logins, sudo commands)
web  : Apache/nginx "combined" access log
app  : JSON-lines application log
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import Event

_IP = r"[0-9a-fA-F:.]+"

# ---------------------------------------------------------------- auth.log ---
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
FAILED_RE = re.compile(rf"Failed (?P<method>[\w-]+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IP})")
ACCEPTED_RE = re.compile(rf"Accepted (?P<method>[\w-]+) for (?P<user>\S+) from (?P<ip>{_IP})")
INVALID_RE = re.compile(rf"Invalid user (?P<user>\S+) from (?P<ip>{_IP})")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")


def _syslog_ts(text: str, year: Optional[int]) -> datetime:
    """Syslog timestamps carry no year, so we have to supply one."""
    text = " ".join(text.split())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    y = year or now.year
    ts = datetime.strptime(f"{y} {text}", "%Y %b %d %H:%M:%S")
    if year is None and ts > now + timedelta(days=1):
        ts = ts.replace(year=y - 1)  # December lines read in January
    return ts


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    line = line.strip()
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        ts = _syslog_ts(m["ts"], year)
    except ValueError:
        return None
    proc = m["proc"].split("/")[-1]
    msg, host = m["msg"], m["host"]

    if proc == "sshd":
        if r := FAILED_RE.search(msg):
            return Event(ts, "auth", "auth_failure", r["ip"], r["user"], host, msg, line, {"method": r["method"]})
        if r := ACCEPTED_RE.search(msg):
            return Event(ts, "auth", "auth_success", r["ip"], r["user"], host, msg, line, {"method": r["method"]})
        if r := INVALID_RE.search(msg):
            # sshd logs this *in addition to* "Failed password", so don't count it as a failure.
            return Event(ts, "auth", "auth_invalid_user", r["ip"], r["user"], host, msg, line)
    elif proc == "sudo":
        if r := SUDO_RE.match(msg):
            return Event(
                ts, "auth", "privilege_cmd", None, r["user"], host, msg, line,
                {"command": r["cmd"].strip(), "target_user": r["target"]},
            )
    return None


# --------------------------------------------------------------- web log -----
WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_web_line(line: str) -> Optional[Event]:
    line = line.strip()
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None
    size = int(m["size"]) if m["size"].isdigit() else 0
    user = None if m["user"] == "-" else m["user"]
    extra = {
        "method": m["method"],
        "path": m["path"],
        "status": int(m["status"]),
        "size": size,
        "referrer": m["ref"] or "",
        "user_agent": m["ua"] or "",
    }
    msg = f'{m["method"]} {m["path"]} -> {m["status"]}'
    return Event(ts, "web", "http_request", m["ip"], user, None, msg, line, extra)


# ------------------------------------------------------------- app (JSON) ----
APP_EVENT_MAP = {"login_failed": "auth_failure", "login_success": "auth_success"}
_APP_CORE_KEYS = {"ts", "event", "user", "ip", "msg"}


def parse_app_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
        name = d["event"]
        ts = datetime.fromisoformat(str(d["ts"]).replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError):
        return None
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    etype = APP_EVENT_MAP.get(name, f"app_{name}")
    extra = {k: v for k, v in d.items() if k not in _APP_CORE_KEYS}
    return Event(ts, "app", etype, d.get("ip"), d.get("user"), d.get("service"), d.get("msg") or name, line, extra)


PARSERS = {"auth": parse_auth_line, "web": parse_web_line, "app": parse_app_line}
