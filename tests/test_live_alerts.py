"""Phase 2: alerts that grow with an ongoing attack, and detection over a recent window."""
from datetime import datetime

from siem.engine import detect, detect_recent, ingest_file, ingest_lines
from siem.models import Alert
from siem.storage import Storage
from siem.tail import FileTailer


def make_alert(count=5, desc="5 failures", key="K1", severity="high"):
    return Alert(rule_id="AUTH-001", title="Brute-force login attempt", severity=severity,
                 timestamp=datetime(2026, 11, 24, 10, 0, 0), description=desc, src_ip="203.0.113.9",
                 event_count=count, evidence=["line"], dedup_key=key)


def failed(day, hh, mm, ss, ip="203.0.113.9"):
    return f"Nov {day} {hh:02d}:{mm:02d}:{ss:02d} srv01 sshd[1]: Failed password for root from {ip} port 22 ssh2\n"


def feed(store, path, text):
    with open(path, "ab") as fh:
        fh.write(text.encode())


# ------------------------------------------------------------------- storage ----
def test_upsert_reports_new_updated_and_unchanged(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    new, upd = s.upsert_alerts([make_alert()])
    assert (len(new), len(upd)) == (1, 0)

    new, upd = s.upsert_alerts([make_alert()])                 # identical => nothing to do
    assert (len(new), len(upd)) == (0, 0)

    new, upd = s.upsert_alerts([make_alert(count=9, desc="9 failures")])   # the attack grew
    assert (len(new), len(upd)) == (0, 1)
    row = s.fetch_alerts()[0]
    assert row["event_count"] == 9 and row["description"] == "9 failures"
    assert s.counts()["alerts"] == 1                            # updated in place, not duplicated


def test_update_keeps_the_original_row_and_creation_time(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    s.upsert_alerts([make_alert()])
    before = s.fetch_alerts()[0]
    s.upsert_alerts([make_alert(count=7, desc="7 failures", severity="critical")])
    after = s.fetch_alerts()[0]
    assert (after["id"], after["created_at"]) == (before["id"], before["created_at"])
    assert after["severity"] == "critical"


def test_same_key_twice_in_one_batch_does_not_crash(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    new, upd = s.upsert_alerts([make_alert(), make_alert(count=8, desc="other")])
    assert (len(new), len(upd)) == (1, 0)
    assert s.counts()["alerts"] == 1


def test_insert_alerts_still_returns_the_number_of_new_alerts(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    assert s.insert_alerts([make_alert(key="A"), make_alert(key="B")]) == 2
    assert s.insert_alerts([make_alert(key="A"), make_alert(key="C")]) == 1


def test_large_batches_work(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    batch = [make_alert(key=f"K{i}") for i in range(1200)]       # more than one 500-key chunk
    assert len(s.upsert_alerts(batch)[0]) == 1200
    assert len(s.upsert_alerts(batch)[0]) == 0


def test_newest_event_time(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(failed(24, 10, 0, 1) + failed(24, 10, 0, 9))
    s = Storage(str(tmp_path / "s.db"))
    assert s.newest_event_time() is None
    ingest_lines(s, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)
    assert s.newest_event_time() == datetime(2026, 11, 24, 10, 0, 9)


# ------------------------------------------------------------------ live growth ----
def test_a_growing_attack_updates_one_alert_instead_of_creating_many(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("")
    t, s = FileTailer(f), Storage(str(tmp_path / "s.db"))

    def step(first_sec, how_many):
        feed(s, f, "".join(failed(24, 10, 0, first_sec + 3 * i) for i in range(how_many)))
        ingest_lines(s, t.poll(), "auth", str(f), year=2026)
        return detect_recent(s)

    r = step(0, 4)                                  # 4 failures: below the threshold
    assert (r.new, r.updated) == ([], [])
    r = step(12, 1)                                 # the 5th arrives: alert is born
    assert len(r.new) == 1 and r.new[0].event_count == 5
    r = step(15, 3)                                 # attack continues: same alert grows
    assert r.new == [] and len(r.updated) == 1 and r.updated[0].event_count == 8
    r = step(24, 4)
    assert r.new == [] and len(r.updated) == 1 and r.updated[0].event_count == 12

    alerts = s.fetch_alerts()
    assert len(alerts) == 1                         # never one alert per new line
    assert alerts[0]["event_count"] == 12
    assert "12 failed logins" in alerts[0]["description"]


def test_checking_again_with_no_new_events_changes_nothing(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("".join(failed(24, 10, 0, 3 * i) for i in range(6)))
    s = Storage(str(tmp_path / "s.db"))
    ingest_lines(s, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)
    first = detect_recent(s)
    again = detect_recent(s)
    assert len(first.new) == 1
    assert (again.new, again.updated) == ([], [])
    assert again.found == first.found


def test_batch_detect_also_grows_existing_alerts(tmp_path):
    """Uploading a bigger version of a file later must update the alert, not leave it frozen."""
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("".join(failed(24, 15, 0, 3 * i) for i in range(5)))
    b.write_text("".join(failed(24, 15, 0, 3 * i) for i in range(8)))   # the same 5 lines + 3 more
    s = Storage(str(tmp_path / "s.db"))
    assert ingest_file(s, str(a), "auth", year=2026).new == 5
    assert detect(s) == (1, 1)
    assert s.fetch_alerts()[0]["event_count"] == 5
    assert ingest_file(s, str(b), "auth", year=2026).new == 3           # only the 3 extra lines are new
    assert detect(s) == (1, 0)                                          # not a new alert ...
    assert s.fetch_alerts()[0]["event_count"] == 8                      # ... but the old one grew
    assert s.counts()["alerts"] == 1


# --------------------------------------------------------------- recent window ----
def test_detect_recent_ignores_events_older_than_the_lookback(tmp_path):
    f = tmp_path / "auth.log"
    old = "".join(failed(21, 10, 0, 3 * i, ip="198.51.100.1") for i in range(6))   # 3 days earlier
    recent = "".join(failed(24, 10, 0, 3 * i, ip="203.0.113.9") for i in range(6))
    f.write_text(old + recent)
    s = Storage(str(tmp_path / "s.db"))
    ingest_lines(s, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)

    r = detect_recent(s, lookback_s=3600)
    assert r.found == 1 and [a.src_ip for a in r.new] == ["203.0.113.9"]

    wide = detect_recent(s, lookback_s=5 * 24 * 3600)   # a wide window sees both attackers
    assert wide.found == 2 and [a.src_ip for a in wide.new] == ["198.51.100.1"]


def test_detect_recent_on_an_empty_database_is_safe(tmp_path):
    r = detect_recent(Storage(str(tmp_path / "s.db")))
    assert (r.found, r.new, r.updated) == (0, [], [])
