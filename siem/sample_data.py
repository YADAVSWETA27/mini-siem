"""Synthetic log generator for demos and tests.

Creates three realistic log files (auth.log, access.log, app.log) containing a day of benign
background activity plus several injected attack scenarios, all using RFC 5737 documentation
IP addresses (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) so nothing here points at real hosts.

Scenarios (when ``include_attacks=True``)
-----------------------------------------
1. 203.0.113.45  web probing with sqlmap + path traversal, then SSH brute force, a successful
                 login as 'admin', and sudo abuse (root shell + new user)      -> multi-stage attack
2. 198.51.100.23 XSS attempts, then password spraying across 14 accounts
3. 192.0.2.99    nikto-style directory enumeration (burst of 404s)
4. 203.0.113.99  OS command injection / LFI
5. 'mallory'     off-hours admin grant and a 25,000-record export (insider / stolen account)
6. 198.51.100.77 harmless-looking traffic from an IP on the threat-intel blocklist
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode

USERS = ["alice", "bob", "carol", "dave", "erin"]
BENIGN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.4.0",
]
BENIGN_PATHS = ["/", "/index.html", "/login", "/dashboard", "/api/v1/items", "/api/v1/items?page=2",
                "/products?id=12", "/products?id=87", "/search?q=laptop+stand", "/static/app.js",
                "/static/style.css", "/about", "/contact", "/favicon.ico"]
BLOCKLIST_IP = "198.51.100.77"


@dataclass
class SampleFiles:
    auth: str
    web: str
    app: str
    blocklist: str
    year: int  # syslog lines have no year; pass this to the auth parser


def generate(out_dir: str, base_time: Optional[datetime] = None, include_attacks: bool = True,
             seed: int = 7) -> SampleFiles:
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if base_time is None:  # yesterday (UTC), so all events are in the past
        base_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    day = base_time.replace(hour=0, minute=0, second=0, microsecond=0)

    def at(h: int, m: int = 0, s: int = 0) -> datetime:
        return day + timedelta(hours=h, minutes=m, seconds=s)

    auth: list[tuple[datetime, str]] = []
    web: list[tuple[datetime, str]] = []
    app: list[tuple[datetime, str]] = []

    def syslog(ts, proc, msg, host="srv01"):
        return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {proc}[{rng.randint(1000, 60000)}]: {msg}"

    def access(ts, ip, path, status, ua, method="GET", size=None):
        size = size if size is not None else rng.randint(200, 20000)
        return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'

    def applog(ts, event, user, ip, level="INFO", **kw):
        d = {"ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "service": "webapp", "level": level,
             "event": event, "user": user, "ip": ip, **kw}
        return json.dumps(d)

    internal = lambda: f"10.0.{rng.randint(0, 3)}.{rng.randint(2, 250)}"
    external = lambda: f"100.64.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    working_hours = lambda: at(8) + timedelta(seconds=rng.randint(0, 10 * 3600))

    # ---------------------------------------------------------- benign noise --
    for _ in range(30):  # normal SSH logins
        ts, user, ip = working_hours(), rng.choice(USERS), internal()
        auth.append((ts, syslog(ts, "sshd", f"Accepted publickey for {user} from {ip} port {rng.randint(30000, 60000)} ssh2")))
    for user in rng.sample(USERS, 3):  # a single typo, then success
        ts, ip = working_hours(), internal()
        auth.append((ts, syslog(ts, "sshd", f"Failed password for {user} from {ip} port 40222 ssh2")))
        ts2 = ts + timedelta(seconds=8)
        auth.append((ts2, syslog(ts2, "sshd", f"Accepted password for {user} from {ip} port 40224 ssh2")))
    for _ in range(10):  # routine admin work
        ts, user = working_hours(), rng.choice(USERS)
        cmd = rng.choice(["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u sshd"])
        auth.append((ts, syslog(ts, "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")))

    pool = [internal() for _ in range(12)] + [external() for _ in range(18)]
    for _ in range(450):  # normal web traffic
        ts, ip = working_hours(), rng.choice(pool)
        r = rng.random()
        status = 200 if r < 0.84 else 304 if r < 0.92 else 301 if r < 0.96 else 404
        web.append((ts, access(ts, ip, rng.choice(BENIGN_PATHS), status, rng.choice(BENIGN_UA))))

    for _ in range(60):  # normal app logins
        ts, user = working_hours(), rng.choice(USERS)
        app.append((ts, applog(ts, "login_success", user, internal())))
    for _ in range(6):  # forgotten passwords
        ts, user = working_hours(), rng.choice(USERS)
        app.append((ts, applog(ts, "login_failed", user, internal(), level="WARN")))
    for _ in range(10):  # small, routine exports
        ts, user = working_hours(), rng.choice(USERS)
        app.append((ts, applog(ts, "data_export", user, internal(), records=rng.randint(20, 400), dataset="orders")))
    for _ in range(3):  # non-admin role changes
        ts = working_hours()
        app.append((ts, applog(ts, "role_change", "carol", internal(), target_user=rng.choice(USERS),
                               old_role="viewer", new_role="editor")))

    if include_attacks:
        # ---- 1. 203.0.113.45: web probing -> SSH brute force -> takeover -> sudo abuse
        a1 = "203.0.113.45"
        sqli = ["1' OR '1'='1", "1 UNION SELECT username,password FROM users--", "1; SELECT SLEEP(5)--",
                "1' OR 1=1--", "1 UNION SELECT NULL,table_name FROM information_schema.tables--", "admin'--"]
        for i in range(12):
            ts = at(2, 30) + timedelta(seconds=i * 20 + rng.randint(0, 5))
            path = "/products.php?" + urlencode({"id": sqli[i % len(sqli)]})
            web.append((ts, access(ts, a1, path, 500 if i % 3 == 0 else 200, "sqlmap/1.7.11#stable (https://sqlmap.org)")))
        for i in range(3):
            ts = at(2, 36) + timedelta(seconds=i * 15)
            path = "/download?file=" + quote("../../../../etc/passwd", safe="")
            web.append((ts, access(ts, a1, path, 403, "sqlmap/1.7.11#stable (https://sqlmap.org)")))
        for i in range(40):
            ts = at(2, 40) + timedelta(seconds=i * 4 + rng.randint(0, 2))
            user, port = rng.choice(["root", "admin", "ubuntu", "test"]), rng.randint(30000, 60000)
            if user in ("ubuntu", "test"):
                auth.append((ts, syslog(ts, "sshd", f"Invalid user {user} from {a1} port {port}")))
                auth.append((ts, syslog(ts, "sshd", f"Failed password for invalid user {user} from {a1} port {port} ssh2")))
            else:
                auth.append((ts, syslog(ts, "sshd", f"Failed password for {user} from {a1} port {port} ssh2")))
        ts = at(2, 44, 30)
        auth.append((ts, syslog(ts, "sshd", f"Accepted password for admin from {a1} port 51234 ssh2")))
        ts = at(2, 47)
        auth.append((ts, syslog(ts, "sudo", "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")))
        ts = at(2, 49)
        auth.append((ts, syslog(ts, "sudo", "admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor")))

        # ---- 2. 198.51.100.23: XSS then password spraying
        a2 = "198.51.100.23"
        for i, payload in enumerate(["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(document.cookie)"]):
            ts = at(11, 10) + timedelta(seconds=i * 20)
            web.append((ts, access(ts, a2, "/search?" + urlencode({"q": payload}), 200, BENIGN_UA[0])))
        spray_users = USERS + ["frank", "grace", "heidi", "ivan", "judy", "mallory", "oscar", "peggy", "trent"]
        for i, user in enumerate(spray_users):
            ts = at(11, 15) + timedelta(seconds=i * 8)
            auth.append((ts, syslog(ts, "sshd", f"Failed password for {user} from {a2} port {rng.randint(30000, 60000)} ssh2")))

        # ---- 3. 192.0.2.99: nikto-style enumeration
        names = ["admin", "backup.zip", ".git/config", "phpmyadmin/", "wp-login.php", ".env",
                 "config.php", "server-status", "test/", "cgi-bin/test.cgi"]
        for i in range(60):
            ts = at(14, 5) + timedelta(seconds=i)
            web.append((ts, access(ts, "192.0.2.99", f"/{names[i % len(names)]}", 404 if i % 10 else 403,
                                   "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)")))

        # ---- 4. 203.0.113.99: command injection / LFI
        for i, payload in enumerate(["127.0.0.1; cat /etc/passwd", "127.0.0.1 && whoami"]):
            ts = at(16, 20) + timedelta(seconds=i * 30)
            web.append((ts, access(ts, "203.0.113.99", "/cgi-bin/ping.cgi?" + urlencode({"host": payload}), 500, BENIGN_UA[3])))

        # ---- 5. mallory: off-hours admin grant + bulk export
        ts = at(3, 10)
        app.append((ts, applog(ts, "login_success", "mallory", "192.0.2.50")))
        ts = at(3, 12)
        app.append((ts, applog(ts, "role_change", "mallory", "192.0.2.50", target_user="mallory",
                               old_role="viewer", new_role="admin")))
        ts = at(9, 30)
        app.append((ts, applog(ts, "data_export", "mallory", "192.0.2.50", records=25000, dataset="customers")))

        # ---- 6. blocklisted IP
        for i in range(3):
            ts = at(12) + timedelta(minutes=i * 2)
            web.append((ts, access(ts, BLOCKLIST_IP, rng.choice(BENIGN_PATHS), 200, BENIGN_UA[2])))

    paths = {"auth": out / "auth.log", "web": out / "access.log", "app": out / "app.log"}
    for key, lines in (("auth", auth), ("web", web), ("app", app)):
        lines.sort(key=lambda x: x[0])
        paths[key].write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
    blocklist = out / "blocklist.txt"
    blocklist.write_text(f"# sample threat-intel blocklist\n{BLOCKLIST_IP}\n203.0.113.200\n", encoding="utf-8")
    return SampleFiles(str(paths["auth"]), str(paths["web"]), str(paths["app"]), str(blocklist), day.year)
