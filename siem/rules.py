"""Detection rules.

Every rule is a plain function ``(rule, events, cfg) -> list[Alert]`` registered with the
``@rule`` decorator. Correlation rules run *after* the normal rules and operate on the
alerts they produced (``@correlation_rule``), which is how single-source signals are
combined into higher-confidence, multi-source detections.

Adding a rule = writing one function. See README.md ("Adding your own rule").
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterator, Optional
from urllib.parse import unquote_plus

from .models import Alert, Event

DEFAULT_CONFIG: dict = {
    "brute_force_threshold": 5,          # failed logins from one IP ...
    "brute_force_window_s": 300,         # ... within this many seconds
    "spray_users": 5,                    # distinct usernames tried by one IP ...
    "spray_window_s": 600,               # ... within this many seconds
    "success_after_fail_threshold": 5,   # failures before a success from the same IP ...
    "success_after_fail_window_s": 600,  # ... within this many seconds
    "pattern_cluster_gap_s": 600,        # merge web-attack hits closer together than this
    "enum_404_threshold": 20,            # 404s from one IP ...
    "enum_404_window_s": 120,            # ... within this many seconds
    "large_export_records": 10_000,      # single export larger than this is suspicious
    "offhours_start": 22,                # UTC hour when "off-hours" begins
    "offhours_end": 5,                   # UTC hour when "off-hours" ends
    "postcompromise_window_s": 3600,     # sudo abuse this soon after a takeover => correlated
    "blocklist": [],                     # known-bad IPs (threat intel)
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    mitre: str
    description: str
    fn: Callable


RULES: list[Rule] = []
CORRELATION_RULES: list[Rule] = []


def _register(target: list, id: str, title: str, severity: str, mitre: str, description: str):
    def deco(fn):
        target.append(Rule(id, title, severity, mitre, description, fn))
        return fn
    return deco


def rule(id, title, severity, mitre, description):
    return _register(RULES, id, title, severity, mitre, description)


def correlation_rule(id, title, severity, mitre, description):
    return _register(CORRELATION_RULES, id, title, severity, mitre, description)


def all_rules() -> list[Rule]:
    return RULES + CORRELATION_RULES


# ------------------------------------------------------------------ helpers --
def _bursts(events: list[Event], threshold: int, window_s: int) -> Iterator[list[Event]]:
    """Yield groups of >= ``threshold`` events that fall within ``window_s`` of each other.

    A burst keeps growing while consecutive events are less than ``window_s`` apart, so a
    long-running attack produces ONE alert instead of one alert per sliding window.
    """
    evs = sorted(events, key=lambda e: e.timestamp)
    window = timedelta(seconds=window_s)
    n, i, k = len(evs), 0, 0
    while i < n:
        k = max(k, i)
        while k < n and evs[k].timestamp - evs[i].timestamp <= window:
            k += 1
        if k - i >= threshold:
            end = k
            while end < n and evs[end].timestamp - evs[end - 1].timestamp <= window:
                end += 1
            yield evs[i:end]
            i = k = end
        else:
            i += 1


def _clusters(events: list[Event], gap_s: int) -> Iterator[list[Event]]:
    return _bursts(events, 1, gap_s)


def _span(evs: list[Event]) -> str:
    a, b = evs[0].timestamp, evs[-1].timestamp
    return f"{a:%H:%M:%S}-{b:%H:%M:%S} UTC" if a != b else f"{a:%H:%M:%S} UTC"


def _alert(r: Rule, evs: list[Event], description: str, *, ip: Optional[str] = None,
           user: Optional[str] = None, severity: Optional[str] = None,
           ts: Optional[datetime] = None, count: Optional[int] = None, key_extra: str = "") -> Alert:
    ts = ts or evs[0].timestamp
    key = "|".join([r.id, ip or "", user or "", ts.isoformat(), key_extra])
    return Alert(
        rule_id=r.id, title=r.title, severity=severity or r.severity, timestamp=ts,
        description=description, src_ip=ip, username=user, mitre=r.mitre,
        event_count=count or len(evs), evidence=[e.raw for e in evs[:25]], dedup_key=key,
    )


def _by_ip(events: list[Event], predicate) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.src_ip and predicate(e):
            out[e.src_ip].append(e)
    return out


def _decoded_path(e: Event) -> str:
    # decode twice so double-encoded payloads (%2527) are caught as well
    return unquote_plus(unquote_plus(e.extra.get("path", "")))


# =========================================================== authentication ==
@rule("AUTH-001", "Brute-force login attempt", "high", "T1110.001",
      "Many failed logins from one IP against a small set of accounts in a short time.")
def brute_force(r, events, cfg):
    out = []
    for ip, evs in _by_ip(events, lambda e: e.event_type == "auth_failure").items():
        for burst in _bursts(evs, cfg["brute_force_threshold"], cfg["brute_force_window_s"]):
            users = sorted({e.username for e in burst if e.username})
            if len(users) >= cfg["spray_users"]:
                continue  # many different accounts => password spraying (AUTH-002)
            out.append(_alert(
                r, burst,
                f"{len(burst)} failed logins from {ip} against {len(users)} account(s) "
                f"({', '.join(users[:5])}) between {_span(burst)}.",
                ip=ip))
    return out


@rule("AUTH-002", "Password spraying", "high", "T1110.003",
      "One IP trying many different usernames - typical of credential-stuffing / spraying.")
def password_spraying(r, events, cfg):
    out = []
    for ip, evs in _by_ip(events, lambda e: e.event_type == "auth_failure").items():
        for burst in _bursts(evs, cfg["spray_users"], cfg["spray_window_s"]):
            users = {e.username for e in burst if e.username}
            if len(users) >= cfg["spray_users"]:
                out.append(_alert(
                    r, burst,
                    f"{ip} failed to log in as {len(users)} different users "
                    f"({len(burst)} attempts) between {_span(burst)}.",
                    ip=ip))
    return out


@rule("AUTH-003", "Successful login after repeated failures", "critical", "T1078",
      "A login succeeded from an IP that had just failed many times - likely account takeover.")
def success_after_failures(r, events, cfg):
    window = timedelta(seconds=cfg["success_after_fail_window_s"])
    fails = _by_ip(events, lambda e: e.event_type == "auth_failure")
    out = []
    for e in events:
        if e.event_type != "auth_success" or not e.src_ip:
            continue
        prior = [f for f in fails.get(e.src_ip, []) if timedelta(0) <= e.timestamp - f.timestamp <= window]
        if len(prior) >= cfg["success_after_fail_threshold"]:
            out.append(_alert(
                r, prior[-10:] + [e],
                f"'{e.username}' logged in from {e.src_ip} at {e.timestamp:%H:%M:%S} UTC right after "
                f"{len(prior)} failed attempts from the same IP. Treat the account as compromised.",
                ip=e.src_ip, user=e.username, ts=e.timestamp, count=len(prior) + 1))
    return out


# ============================================================ web attacks ====
def _pattern_rule(id, title, severity, mitre, description, regex, what):
    pat = re.compile(regex, re.I)

    @rule(id, title, severity, mitre, description)
    def _fn(r, events, cfg):
        hits = _by_ip(events, lambda e: e.event_type == "http_request" and pat.search(_decoded_path(e)))
        out = []
        for ip, evs in hits.items():
            for cluster in _clusters(evs, cfg["pattern_cluster_gap_s"]):
                sample = _decoded_path(cluster[0])[:90]
                out.append(_alert(
                    r, cluster,
                    f"{len(cluster)} request(s) from {ip} contained {what} between {_span(cluster)}. "
                    f"First payload: {sample}",
                    ip=ip))
        return out
    return _fn


_pattern_rule(
    "WEB-001", "SQL injection attempt", "high", "T1190",
    "HTTP requests containing SQL injection payloads.",
    r"(\bunion\b.{0,20}\bselect\b|\bor\b\s*'?1'?\s*=\s*'?1|'\s*or\s*'[^']*'\s*=\s*'"
    r"|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|information_schema|;\s*drop\s+table|'\s*--)",
    "SQL injection payloads")

_pattern_rule(
    "WEB-002", "Cross-site scripting (XSS) attempt", "medium", "T1190",
    "HTTP requests containing script injection payloads.",
    r"(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*img[^>]+src\s*=|<\s*svg[^>]*onload)",
    "XSS payloads")

_pattern_rule(
    "WEB-003", "Path traversal / local file inclusion", "high", "T1190",
    "HTTP requests trying to read files outside the web root.",
    r"(\.\.[/\\]|/etc/passwd|/etc/shadow|c:\\windows|boot\.ini|/proc/self/environ)",
    "path-traversal / LFI patterns")

_pattern_rule(
    "WEB-004", "OS command injection attempt", "high", "T1059",
    "HTTP requests chaining shell commands onto a parameter.",
    r"(?:;|\|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
    "shell command-injection patterns")

SCANNER_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|nessus|zgrab)", re.I)


@rule("WEB-005", "Known attack/scanner tool detected", "medium", "T1595.002",
      "User-Agent matches a well-known vulnerability scanner or exploitation tool.")
def scanner_user_agent(r, events, cfg):
    hits = _by_ip(events, lambda e: e.event_type == "http_request" and SCANNER_RE.search(e.extra.get("user_agent", "")))
    out = []
    for ip, evs in hits.items():
        for cluster in _clusters(evs, cfg["pattern_cluster_gap_s"]):
            tools = sorted({m.group(1).lower() for e in cluster if (m := SCANNER_RE.search(e.extra["user_agent"]))})
            out.append(_alert(r, cluster,
                              f"{len(cluster)} request(s) from {ip} used scanner/exploit tool(s): "
                              f"{', '.join(tools)} ({_span(cluster)}).", ip=ip))
    return out


@rule("WEB-006", "Directory / file enumeration", "medium", "T1595.003",
      "Burst of 404 responses to one IP - forced browsing or wordlist scanning.")
def dir_enumeration(r, events, cfg):
    out = []
    for ip, evs in _by_ip(events, lambda e: e.event_type == "http_request" and e.extra.get("status") == 404).items():
        for burst in _bursts(evs, cfg["enum_404_threshold"], cfg["enum_404_window_s"]):
            out.append(_alert(r, burst,
                              f"{len(burst)} requests from {ip} returned 404 between {_span(burst)} "
                              f"(e.g. {burst[0].extra['path']}, {burst[1].extra['path']}).", ip=ip))
    return out


# =================================================== host / app / threat intel =
SUSPICIOUS_SUDO_RE = re.compile(
    r"(/bin/(?:ba|z)?sh\b|\bsu\s*-?\s*$|\b(?:useradd|adduser|usermod|visudo)\b|/etc/shadow"
    r"|chmod\s+(?:-R\s+)?[0-7]?777|\bnc\b.*\s-e\b|(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh)", re.I)


@rule("SYS-001", "Suspicious privileged command (sudo)", "medium", "T1548.003",
      "sudo used to spawn a root shell, create users, open permissions, or pipe a download to a shell.")
def suspicious_sudo(r, events, cfg):
    out = []
    for e in events:
        if e.event_type == "privilege_cmd" and SUSPICIOUS_SUDO_RE.search(e.extra.get("command", "")):
            out.append(_alert(
                r, [e],
                f"{e.username} ran as {e.extra.get('target_user', 'root')}: {e.extra['command']}",
                user=e.username, key_extra=e.uid[:8] or e.extra["command"]))
    return out


@rule("APP-001", "Unusually large data export", "high", "T1213",
      "A single export returned far more records than normal - possible data theft.")
def large_export(r, events, cfg):
    out = []
    for e in events:
        n = e.extra.get("records", 0) if e.event_type == "app_data_export" else 0
        if isinstance(n, (int, float)) and n >= cfg["large_export_records"]:
            out.append(_alert(
                r, [e],
                f"{e.username} exported {int(n):,} records of '{e.extra.get('dataset', '?')}' "
                f"from {e.src_ip} at {e.timestamp:%H:%M:%S} UTC.",
                ip=e.src_ip, user=e.username, key_extra=e.uid[:8]))
    return out


def _off_hours(ts: datetime, cfg: dict) -> bool:
    start, end = cfg["offhours_start"], cfg["offhours_end"]
    return ts.hour >= start or ts.hour < end


@rule("APP-002", "Admin privileges granted", "medium", "T1098",
      "A user was given an administrator role (severity is raised outside business hours).")
def admin_granted(r, events, cfg):
    out = []
    for e in events:
        if e.event_type == "app_role_change" and str(e.extra.get("new_role", "")).lower() in {"admin", "superuser", "root"}:
            off = _off_hours(e.timestamp, cfg)
            target = e.extra.get("target_user", e.username)
            out.append(_alert(
                r, [e],
                f"{e.username} granted '{e.extra.get('new_role')}' to {target} at {e.timestamp:%H:%M:%S} UTC"
                f"{' (OFF-HOURS)' if off else ''}.",
                ip=e.src_ip, user=e.username, severity="high" if off else None, key_extra=e.uid[:8]))
    return out


@rule("TI-001", "Traffic from known-bad IP (threat intel)", "high", "",
      "Activity from an address on the configured blocklist.")
def blocklisted_ip(r, events, cfg):
    bad = set(cfg.get("blocklist") or [])
    out = []
    for ip, evs in _by_ip(events, lambda e: e.src_ip in bad).items():
        for cluster in _clusters(evs, cfg["pattern_cluster_gap_s"]):
            kinds = sorted({e.source for e in cluster})
            out.append(_alert(r, cluster,
                              f"{len(cluster)} event(s) from blocklisted IP {ip} in {', '.join(kinds)} logs ({_span(cluster)}).",
                              ip=ip))
    return out


# ============================================================= correlation ===
@correlation_rule("COR-001", "Multi-stage attack from a single IP", "critical", "TA0001, TA0006",
                  "The same IP triggered both web-attack and authentication alerts (recon -> credential attack).")
def multi_stage(r, alerts, cfg):
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        if a.src_ip:
            by_ip[a.src_ip].append(a)
    out = []
    for ip, al in by_ip.items():
        if {"AUTH", "WEB"} <= {a.rule_id.split("-")[0] for a in al}:
            al = sorted(al, key=lambda a: a.timestamp)
            out.append(Alert(
                rule_id=r.id, title=r.title, severity=r.severity, timestamp=al[0].timestamp,
                description=(f"{ip} triggered {len(al)} alerts across web and authentication logs "
                             f"({', '.join(sorted({a.rule_id for a in al}))}). Likely one attacker moving from "
                             f"web probing to credential attacks."),
                src_ip=ip, mitre=r.mitre, event_count=sum(a.event_count for a in al),
                evidence=[f"[{a.severity.upper()}] {a.rule_id} {a.title} @ {a.timestamp:%H:%M:%S}" for a in al],
                dedup_key=f"{r.id}|{ip}"))
    return out


@correlation_rule("COR-002", "Privilege escalation after account takeover", "critical", "T1078, T1548.003",
                  "A compromised account ran suspicious sudo commands shortly after the takeover.")
def post_compromise(r, alerts, cfg):
    window = timedelta(seconds=cfg["postcompromise_window_s"])
    takeovers = [a for a in alerts if a.rule_id == "AUTH-003" and a.username]
    sudos = [a for a in alerts if a.rule_id == "SYS-001" and a.username]
    out = []
    for t in takeovers:
        hits = sorted((s for s in sudos if s.username == t.username
                       and timedelta(0) <= s.timestamp - t.timestamp <= window), key=lambda a: a.timestamp)
        if hits:
            out.append(Alert(
                rule_id=r.id, title=r.title, severity=r.severity, timestamp=t.timestamp,
                description=(f"'{t.username}' was taken over from {t.src_ip} at {t.timestamp:%H:%M:%S} UTC and then ran "
                             f"{len(hits)} suspicious privileged command(s) within "
                             f"{int(window.total_seconds() // 60)} minutes."),
                src_ip=t.src_ip, username=t.username, mitre=r.mitre,
                event_count=t.event_count + sum(h.event_count for h in hits),
                evidence=[f"AUTH-003 @ {t.timestamp:%H:%M:%S}: {t.description}"]
                         + [f"SYS-001 @ {h.timestamp:%H:%M:%S}: {h.description}" for h in hits],
                dedup_key=f"{r.id}|{t.username}|{t.timestamp.isoformat()}"))
    return out


# ================================================================= engine ====
def run_detection(events: list[Event], cfg: Optional[dict] = None) -> list[Alert]:
    """Run every rule over ``events`` and return all alerts, oldest first."""
    cfg = {**DEFAULT_CONFIG, **(cfg or {})}
    events = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    for r in RULES:
        alerts.extend(r.fn(r, events, cfg))
    for r in CORRELATION_RULES:
        alerts.extend(r.fn(r, list(alerts), cfg))
    return sorted(alerts, key=lambda a: a.timestamp)
