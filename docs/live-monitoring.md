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
