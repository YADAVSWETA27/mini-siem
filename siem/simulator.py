"""Attack simulator: slowly writes a FAKE attack into log files so you can watch it get detected.

Unlike ``sample_data`` (which creates a whole day of logs in one go), this appends one line at a
time, stamped with the current time, the way a real server would. Start the live watcher first,
then run the simulator, and the alerts appear as the "attack" unfolds.

Everything is invented. Attacker addresses come from the RFC 5737 documentation ranges
(203.0.113.0/24, 198.51.100.0/24), which are reserved and never belong to real hosts.

Scenarios
---------
multistage : web probing with sqlmap -> SSH brute force -> successful login as 'admin' -> sudo abuse
spray      : one IP trying fourteen different usernames (password spraying)
"""
from __future__ import annotations

import os
import random
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import quote, urlencode

SCENARIOS = ("multistage", "spray")
FILENAMES = {"auth": "auth.log", "web": "access.log", "app": "app.log"}

ATTACKER_WEB = "203.0.113.45"
ATTACKER_SPRAY = "198.51.100.23"
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1 UNION SELECT username,password FROM users--",
    "1; SELECT SLEEP(5)--",
    "1' OR 1=1--",
    "1 UNION SELECT NULL,table_name FROM information_schema.tables--",
    "admin'--",
]
BENIGN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
SPRAY_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace",
               "heidi", "ivan", "judy", "mallory", "oscar", "peggy", "trent"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _syslog(ts: datetime, proc: str, msg: str, rng: random.Random) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} srv01 {proc}[{rng.randint(1000, 60000)}]: {msg}"


def _access(ts: datetime, ip: str, path: str, status: int, ua: str, rng: random.Random) -> str:
    return (f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" '
            f'{status} {rng.randint(200, 20000)} "-" "{ua}"')


# A scenario is an ordered list of steps. Each step is (which_file, function that turns
# "the current time" into one log line). The line is only built at the moment it is written,
# so every line carries a fresh timestamp.
def _multistage(rng: random.Random) -> list:
    steps: list = []
    a = ATTACKER_WEB
    ua = "sqlmap/1.7.11#stable (https://sqlmap.org)"
    for path in ("/", "/products?id=12", "/login"):                       # normal visitor
        steps.append(("web", lambda ts, p=path: _access(ts, "10.0.0.7", p, 200, BENIGN_UA, rng)))
    steps.append(("auth", lambda ts: _syslog(
        ts, "sshd", "Accepted publickey for alice from 10.0.0.5 port 50122 ssh2", rng)))
    for i in range(8):                                                    # 1. SQL injection probing
        payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
        steps.append(("web", lambda ts, p=payload: _access(
            ts, a, "/products.php?" + urlencode({"id": p}), 200, ua, rng)))
    for _ in range(2):                                                    # 2. path traversal
        steps.append(("web", lambda ts: _access(
            ts, a, "/download?file=" + quote("../../../../etc/passwd", safe=""), 403, ua, rng)))
    for i in range(12):                                                   # 3. SSH brute force
        user = ("root", "admin")[i % 2]
        steps.append(("auth", lambda ts, u=user: _syslog(
            ts, "sshd", f"Failed password for {u} from {a} port {rng.randint(30000, 60000)} ssh2", rng)))
    steps.append(("auth", lambda ts: _syslog(                             # 4. the attacker gets in
        ts, "sshd", f"Accepted password for admin from {a} port 51234 ssh2", rng)))
    steps.append(("auth", lambda ts: _syslog(                             # 5. and takes over the machine
        ts, "sudo", "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash", rng)))
    steps.append(("auth", lambda ts: _syslog(
        ts, "sudo", "admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor", rng)))
    return steps


def _spray(rng: random.Random) -> list:
    steps: list = [("auth", lambda ts: _syslog(
        ts, "sshd", "Accepted publickey for alice from 10.0.0.5 port 50122 ssh2", rng))]
    for user in SPRAY_USERS:
        steps.append(("auth", lambda ts, u=user: _syslog(
            ts, "sshd", f"Failed password for {u} from {ATTACKER_SPRAY} port {rng.randint(30000, 60000)} ssh2", rng)))
    return steps


_BUILDERS = {"multistage": _multistage, "spray": _spray}


def files_used(scenario: str) -> list[str]:
    """Which log files (auth/web/app) a scenario writes to, so callers know what to watch."""
    if scenario not in _BUILDERS:
        raise ValueError(f"unknown scenario '{scenario}' (choose from {', '.join(SCENARIOS)})")
    return sorted({key for key, _ in _BUILDERS[scenario](random.Random(0))})


def simulate(out_dir: str, scenario: str = "multistage", delay: float = 1.0, seed: int = 7,
             now: Optional[Callable[[], datetime]] = None, sleep: Callable[[float], None] = time.sleep,
             on_write: Optional[Callable[[str, str], None]] = None) -> dict[str, str]:
    """Append the scenario's lines to fresh log files in ``out_dir``, ``delay`` seconds apart.

    ``now`` and ``sleep`` can be replaced (tests use a fake clock so nothing really waits);
    ``on_write(file_key, line)`` is called right after each line is written.
    Returns ``{"auth": path, "web": path, ...}`` for the files that were written.
    """
    if scenario not in _BUILDERS:
        raise ValueError(f"unknown scenario '{scenario}' (choose from {', '.join(SCENARIOS)})")
    now = now or _utcnow
    rng = random.Random(seed)
    steps = _BUILDERS[scenario](rng)

    os.makedirs(out_dir, exist_ok=True)
    paths = {key: os.path.join(out_dir, FILENAMES[key]) for key in sorted({k for k, _ in steps})}
    for path in paths.values():
        open(path, "w", encoding="utf-8").close()  # start from empty files

    for i, (key, make_line) in enumerate(steps):
        line = make_line(now())
        with open(paths[key], "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
        if on_write:
            on_write(key, line)
        if delay and i < len(steps) - 1:
            sleep(delay)
    return paths
