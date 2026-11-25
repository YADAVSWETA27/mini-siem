# Mini-SIEM

A small, readable **Security Information & Event Management** pipeline in Python. It collects logs from three different sources, normalizes them into one schema, runs **15 detection rules** (mapped to MITRE ATT&CK, including cross-source correlation), stores everything in SQLite, and presents alerts in a Streamlit analyst dashboard with an investigation view.

It can analyse finished log files **or watch them live**, raising alerts within about a second as an attack unfolds (near-real-time, by polling).

It mirrors the core loop of a real SOC: **collect -> normalize -> detect -> triage -> investigate.**

![Alert timeline](docs/alert-timeline.png)

## Features

- **Three log sources, one schema**: Linux `auth.log` (sshd + sudo), Apache/nginx combined access logs, JSON-lines application logs. Adding a source means writing one parser function.
- **15 detection rules**: brute force, password spraying, account takeover, SQL injection, XSS, path traversal, command injection, scanner tools, directory enumeration, suspicious sudo, bulk data export, off-hours admin grant, threat-intel blocklist, plus two **correlation rules** that combine alerts across sources.
- **Idempotent**: re-ingesting a file or re-running detection never creates duplicates, while genuinely repeated log lines are still preserved.
- **Analyst dashboard**: KPIs, alert timeline, event volume by source, severity breakdown, top offending IPs, MITRE ATT&CK coverage, a searchable alert table, and an investigation panel showing the raw evidence lines and everything else that IP or user did.
- **Demo data generator**: a day of realistic benign traffic plus six injected attack scenarios, using only RFC 5737 documentation IPs (`203.0.113.x`, `198.51.100.x`, `192.0.2.x`).
- **Live monitoring**: `python cli.py watch` tails log files, saves new events and prints `NEW` / `UPDATED` alerts as they happen. A growing attack *updates* its alert instead of duplicating it. The dashboard has an **Auto-refresh** switch.
- **Attack simulator**: `python cli.py simulate` writes a fake multi-stage attack line by line so you can watch it get detected.
- **97 automated tests**, including boundary tests for every rule, an end-to-end pipeline test, a **false-positive guard** asserting a normal day of traffic raises zero alerts, and tests for the live watcher, simulator and dashboard.

## Architecture

```mermaid
flowchart LR
    A[auth.log<br/>sshd, sudo] --> P
    B[access.log<br/>nginx/apache] --> P
    C[app.log<br/>JSON lines] --> P
    P[Parsers<br/>normalize to Event] --> S[(SQLite<br/>events)]
    S --> R[Detection rules<br/>13 single-source]
    R --> K[Correlation rules<br/>2 cross-source]
    K --> AL[(SQLite<br/>alerts)]
    AL --> D[Streamlit dashboard]
    S --> D
    T[Live tailer<br/>watch] -.-> P
    CLI[cli.py] -.-> P
    CLI -.-> R
```

| Module | Responsibility |
|---|---|
| `siem/models.py` | `Event` and `Alert` dataclasses: the normalized schema everything speaks |
| `siem/parsers.py` | One parser per log format; returns `None` for lines it does not understand |
| `siem/storage.py` | SQLite persistence with de-duplication |
| `siem/rules.py` | All detection and correlation rules plus thresholds (`DEFAULT_CONFIG`) |
| `siem/engine.py` | `ingest_file()`, `ingest_lines()`, `detect()` and `detect_recent()`: the glue |
| `siem/tail.py` | Live file tailer: byte-offset bookmark, partial lines, truncation/rotation |
| `siem/live.py` | `LiveMonitor`: one round = read new lines, save, detect, report changes |
| `siem/simulator.py` | Writes a fake attack slowly into log files (demo and tests) |
| `siem/sample_data.py` | Synthetic log generator with attack scenarios |
| `cli.py` | Command-line interface (`demo`, `ingest`, `detect`, `alerts`, `rules`, `watch`, `simulate`) |
| `dashboard.py` | Streamlit dashboard |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python cli.py demo            # generates sample logs, ingests them, runs detection, prints alerts
streamlit run dashboard.py    # open http://localhost:8501
```


Run the tests: `python -m pytest`

### Using your own logs

```bash
python cli.py ingest --source auth --file /var/log/auth.log --year 2026
python cli.py ingest --source web  --file /var/log/nginx/access.log
python cli.py ingest --source app  --file app.log
python cli.py detect --blocklist my_blocklist.txt
python cli.py alerts --min-severity high
```

You can also upload files from the dashboard sidebar. Only analyze logs from systems you own or are authorized to monitor.

## Live monitoring (near-real-time)

Besides analysing a finished log file, Mini-SIEM can **watch log files while they grow** and raise alerts within about a second of the evidence appearing.

```
# window 1: watch the files (new lines only)
python cli.py watch --auth live-logs/auth.log --web live-logs/access.log

# window 2: write a FAKE multi-stage attack, one log line per second
python cli.py simulate

# window 3: dashboard, then switch on "Auto-refresh" in the sidebar
streamlit run dashboard.py
```

Windows 1 prints `NEW` and `UPDATED` alerts as the attack unfolds: SQL injection probing, then SSH brute force, then a successful login, then sudo abuse, then a correlated critical alert. The brute-force alert is *updated* (its event count grows) rather than duplicated.

### How it works
- **Tailer** (`siem/tail.py`): remembers a byte offset per file (a bookmark) and polls once a second. It waits for incomplete lines, and starts over if a file is truncated or rotated.
- **Safe ingestion** (`siem/engine.py`): each event gets an ID built from its file position, so reading the same line twice never creates a duplicate.
- **Updating alerts** (`Storage.upsert_alerts`): an alert has a stable key, so a growing attack updates one alert instead of freezing at the first few events.
- **Recent-window detection** (`detect_recent`): after new events arrive, the rules re-run over the last 24 hours only (configurable with `--lookback-hours`).
- **Shared database**: SQLite in WAL mode lets the watcher write while the dashboard reads.

### Limitations
- It *polls* once a second; it is near-real-time, not a streaming platform (no Kafka, no push).
- It watches log files on one machine; there is no agent that ships logs from other hosts.
- An attack longer than the lookback window can lose its beginning from the window.
- Log files must be UTF-8/ASCII text (UTF-16 files, such as PowerShell `>>` output, are not read).
- The simulator is fake data built from reserved documentation IP ranges.

## Detection rules

| ID | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| AUTH-001 | Brute-force login attempt | high | T1110.001 |
| AUTH-002 | Password spraying | high | T1110.003 |
| AUTH-003 | Successful login after repeated failures | critical | T1078 |
| WEB-001 | SQL injection attempt | high | T1190 |
| WEB-002 | Cross-site scripting (XSS) attempt | medium | T1190 |
| WEB-003 | Path traversal / local file inclusion | high | T1190 |
| WEB-004 | OS command injection attempt | high | T1059 |
| WEB-005 | Known attack/scanner tool detected | medium | T1595.002 |
| WEB-006 | Directory / file enumeration (404 burst) | medium | T1595.003 |
| SYS-001 | Suspicious privileged command (sudo) | medium | T1548.003 |
| APP-001 | Unusually large data export | high | T1213 |
| APP-002 | Admin privileges granted (high when off-hours) | medium / high | T1098 |
| TI-001 | Traffic from known-bad IP (threat intel) | high | n/a |
| COR-001 | Multi-stage attack from a single IP | critical | TA0001, TA0006 |
| COR-002 | Privilege escalation after account takeover | critical | T1078, T1548.003 |

Design points worth knowing:

- **Bursts, not sliding windows.** A long attack produces *one* alert, not hundreds. A burst keeps growing while consecutive events stay within the window.
- **Brute force vs. spraying are mutually exclusive.** Many failures against few accounts is brute force; many accounts is spraying. The same attempts are not reported twice.
- **Correlation raises confidence.** COR-001 fires when one IP triggers both web-attack and authentication alerts (recon followed by credential attack). COR-002 fires when a taken-over account runs suspicious `sudo` commands within an hour.
- **Double-decoded URLs.** Web payloads are URL-decoded twice so `%2527`-style evasion is still caught.

## Adding your own rule

A rule is one function. Register it and it runs, appears on the dashboard's rules tab, and is counted in the KPIs:

```python
# siem/rules.py
@rule("AUTH-004", "Login from a new country", "medium", "T1078", "Account used from an unusual location.")
def new_country(r, events, cfg):
    out = []
    for e in events:
        if e.event_type == "auth_success" and e.extra.get("country") not in cfg["home_countries"]:
            out.append(_alert(r, [e], f"{e.username} logged in from {e.extra.get('country')}.",
                              ip=e.src_ip, user=e.username))
    return out
```

Then add a test in `tests/test_rules.py` (copy the pattern: build a few `Event`s, call `run_detection`, assert on `rule_id`). For simple regex matching on web requests, call `_pattern_rule(...)` instead; see WEB-001.

## Adding a log source

Write `parse_xxx_line(line) -> Optional[Event]` in `siem/parsers.py`, add it to `PARSERS`, and every rule that keys off `event_type` (`auth_failure`, `auth_success`, ...) works on it immediately. That is the payoff of normalization.

## Limitations (and what I would do next)

Being honest about these is part of the project:

- **Polling, not true streaming.** Live mode checks files once a second and re-runs the rules over a recent window. A production system would ship logs from many hosts through a queue (for example Kafka) and evaluate rules incrementally.
- **SQLite is fine for demos, not for volume.** The `Storage` class is the seam for swapping in Elasticsearch/OpenSearch or Postgres.
- **Regex rules can be evaded.** Attackers obfuscate. Real deployments layer these with anomaly detection and WAF data. Thresholds were tuned against the synthetic data and would need tuning on real traffic.
- **Syslog has no year**, so the `--year` flag exists (and rolls back a year for December lines read in January).
- **UTC only.** Timestamps are normalized to UTC on ingest.
- **No dashboard authentication.** Do not expose it to the internet as-is.

Ideas for extending it: GeoIP/ASN enrichment, Sigma rule import, alert notifications (email/Slack/webhook), Elasticsearch backend, per-user behavioural baselines, an ML anomaly detector as one more rule.


## License

MIT. See the `LICENSE` file. The synthetic data uses reserved documentation IP ranges and contains no real hosts or credentials.