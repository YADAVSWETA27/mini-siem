"""Phase 3: LiveMonitor, the attack simulator and the `watch` / `simulate` commands."""
import re
import sqlite3
from datetime import datetime, timedelta

import pytest

import cli
from siem.live import LiveMonitor
from siem.simulator import FILENAMES, SCENARIOS, files_used, simulate
from siem.storage import Storage


def failed(sec, ip="203.0.113.9", user="root"):
    return f"Nov 24 10:00:{sec:02d} srv01 sshd[1]: Failed password for {user} from {ip} port 22 ssh2\n"


def append(path, text):
    with open(path, "ab") as fh:
        fh.write(text.encode())


class FakeClock:
    """A clock that moves forward each time it is read, so nothing really waits."""
    def __init__(self):
        self.t = datetime(2026, 11, 24, 12, 0, 0)

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += timedelta(seconds=seconds)


# ------------------------------------------------------------------ monitor ----
def test_step_saves_new_lines_and_raises_alert(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    store = Storage(str(tmp_path / "s.db"))
    mon = LiveMonitor(store, [("auth", str(log))], year=2026)
    assert mon.step().new_events == 0
    append(log, "".join(failed(i) for i in range(6)))
    res = mon.step()
    assert res.new_events == 6
    assert [a.rule_id for a in res.new_alerts] == ["AUTH-001"]


def test_idle_step_does_nothing(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    mon = LiveMonitor(Storage(str(tmp_path / "s.db")), [("auth", str(log))], year=2026)
    mon.step()
    res = mon.step()
    assert (res.new_events, res.new_alerts, res.updated_alerts) == (0, [], [])


def test_first_round_checks_events_left_by_earlier_session(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    store = Storage(str(tmp_path / "s.db"))
    log.write_text("".join(failed(i) for i in range(6)))
    from siem.engine import ingest_file
    ingest_file(store, str(log), "auth", year=2026)  # events saved but never checked
    res = LiveMonitor(store, [("auth", str(log))], year=2026).step()
    assert [a.rule_id for a in res.new_alerts] == ["AUTH-001"]


def test_growing_attack_updates_same_alert(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    store = Storage(str(tmp_path / "s.db"))
    mon = LiveMonitor(store, [("auth", str(log))], year=2026)
    mon.step()
    append(log, "".join(failed(i) for i in range(5)))
    assert len(mon.step().new_alerts) == 1
    append(log, "".join(failed(i) for i in range(5, 9)))
    res = mon.step()
    assert res.new_alerts == [] and len(res.updated_alerts) == 1
    assert res.updated_alerts[0].event_count == 9
    assert len(store.fetch_alerts()) == 1


def test_unknown_source_rejected(tmp_path):
    with pytest.raises(ValueError):
        LiveMonitor(Storage(str(tmp_path / "s.db")), [("nope", str(tmp_path / "x.log"))])


def test_blocklist_config_is_used(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    store = Storage(str(tmp_path / "s.db"))
    mon = LiveMonitor(store, [("web", str(log))], cfg={"blocklist": {"203.0.113.9"}})
    mon.step()
    append(log, '203.0.113.9 - - [24/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8"\n')
    res = mon.step()
    assert any("blocklist" in a.title.lower() or "known" in a.title.lower() for a in res.new_alerts)


def test_two_sources_correlate(tmp_path):
    simulate_dir = tmp_path / "logs"
    clock = FakeClock()
    store = Storage(str(tmp_path / "s.db"))
    paths = {k: str(simulate_dir / FILENAMES[k]) for k in files_used("multistage")}
    simulate_dir.mkdir()
    for p in paths.values():
        open(p, "w").close()
    mon = LiveMonitor(store, [(k, p) for k, p in paths.items()], year=2026)
    mon.step()
    seen = []
    simulate(str(simulate_dir), "multistage", 1.0, now=clock.now, sleep=clock.sleep,
             on_write=lambda k, l: seen.extend(a.rule_id for a in mon.step().new_alerts))
    assert "COR-001" in seen


# ---------------------------------------------------------------- simulator ----
def run_sim(tmp_path, scenario):
    clock = FakeClock()
    store = Storage(str(tmp_path / "s.db"))
    out = tmp_path / "logs"
    out.mkdir(exist_ok=True)
    watch = [(k, str(out / FILENAMES[k])) for k in files_used(scenario)]
    for _, p in watch:
        open(p, "w").close()
    mon = LiveMonitor(store, watch, year=clock.now().year)
    mon.step()
    timeline, counts = [], []

    def on_write(key, line):
        r = mon.step()
        timeline.extend(a.rule_id for a in r.new_alerts)
        counts.extend(a.event_count for a in r.updated_alerts if a.rule_id == "AUTH-001")

    simulate(str(out), scenario, 1.0, now=clock.now, sleep=clock.sleep, on_write=on_write)
    return timeline, counts, store


def test_multistage_alerts_appear_in_attack_order(tmp_path):
    timeline, counts, store = run_sim(tmp_path, "multistage")
    assert timeline.index("AUTH-001") < timeline.index("AUTH-003") < timeline.index("COR-002")
    assert counts and counts == sorted(counts)  # the brute-force alert kept growing
    assert counts[-1] > 5


def test_spray_scenario_detects_spraying(tmp_path):
    timeline, _, _ = run_sim(tmp_path, "spray")
    assert "AUTH-002" in timeline and "AUTH-001" not in timeline


def test_simulate_starts_from_fresh_files(tmp_path):
    (tmp_path / "auth.log").write_text("OLD JUNK\n")
    simulate(str(tmp_path), "spray", 0, now=FakeClock().now)
    assert "OLD JUNK" not in (tmp_path / "auth.log").read_text()


def test_unknown_scenario(tmp_path):
    with pytest.raises(ValueError):
        simulate(str(tmp_path), "nope", 0)
    with pytest.raises(ValueError):
        files_used("nope")


def test_simulator_only_uses_documentation_ips(tmp_path):
    for scenario in SCENARIOS:
        simulate(str(tmp_path), scenario, 0, now=FakeClock().now)
    text = "".join(p.read_text() for p in tmp_path.glob("*.log"))
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        assert ip.startswith(("203.0.113.", "198.51.100.", "10.0.0.")), ip


# --------------------------------------------------------------------- CLI ----
def test_cli_simulate_then_watch(tmp_path, capsys):
    logs = str(tmp_path / "logs")
    assert cli.main(["simulate", "--dir", logs, "--scenario", "spray", "--delay", "0"]) == 0
    db = str(tmp_path / "s.db")
    rc = cli.main(["--db", db, "watch", "--auth", logs + "/auth.log", "--from-start",
                   "--max-steps", "1", "--interval", "0", "--year", str(datetime.now().year)])
    out = capsys.readouterr().out
    assert rc == 0 and "NEW" in out and "AUTH-002" in out and "Stopped." in out


def test_cli_watch_with_nothing_to_watch(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "s.db"), "watch"]) == 2
    assert "Nothing to watch" in capsys.readouterr().out


# --------------------------------------------------------------- database ----
def test_wal_mode_and_concurrent_read_write(tmp_path):
    path = str(tmp_path / "s.db")
    writer, reader = Storage(path), Storage(path)
    assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    writer.conn.execute("BEGIN")
    writer.conn.execute("DELETE FROM events")
    assert reader.counts()["events"] == 0  # readable while a write is open
    writer.conn.rollback()
