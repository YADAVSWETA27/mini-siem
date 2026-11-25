"""Phase 4: the dashboard renders, and live mode shows data that arrives while it is open."""
import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from siem.live import LiveMonitor
from siem.storage import Storage

DASHBOARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard.py")


def new_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_DB", str(tmp_path / "dash.db"))
    return AppTest.from_file(DASHBOARD, default_timeout=60)


def texts(at):
    return " ".join(str(c.value) for c in at.caption) + " ".join(str(m.value) for m in at.markdown)


def test_empty_database_shows_hint(tmp_path, monkeypatch):
    at = new_app(tmp_path, monkeypatch).run()
    assert not at.exception
    assert any("database is empty" in i.value for i in at.info)


def test_live_mode_on_empty_database_says_waiting(tmp_path, monkeypatch):
    at = new_app(tmp_path, monkeypatch).run()
    at.toggle(key="live_mode").set_value(True).run()
    assert not at.exception
    assert any("Waiting for events" in i.value for i in at.info)


def test_demo_data_renders_without_errors(tmp_path, monkeypatch):
    at = new_app(tmp_path, monkeypatch).run()
    next(b for b in at.button if b.label == "Load demo data").click().run()
    assert not at.exception
    assert len(at.metric) == 5


def test_live_mode_picks_up_events_written_after_it_opened(tmp_path, monkeypatch):
    db = str(tmp_path / "dash.db")
    log = tmp_path / "auth.log"
    log.write_text("")
    at = new_app(tmp_path, monkeypatch).run()
    at.toggle(key="live_mode").set_value(True).run()
    assert any("Waiting for events" in i.value for i in at.info)

    # the "watcher" (a second connection to the same database) saves a brute-force attack
    mon = LiveMonitor(Storage(db), [("auth", str(log))], year=2026)
    mon.step()
    with open(log, "ab") as fh:
        for i in range(6):
            fh.write(f"Nov 24 10:00:{i:02d} srv01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n".encode())
    assert mon.step().new_alerts

    at.run()  # what the timer does in the browser
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Events ingested"] == "6" and metrics["Alerts"] == "1"
    assert "Live: refreshed" in texts(at)
