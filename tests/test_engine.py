"""End-to-end tests: generate logs -> ingest -> detect -> store, plus CLI and storage behaviour."""
from datetime import datetime

import pytest

from cli import main as cli_main
from siem import sample_data
from siem.engine import detect, ingest_file, load_blocklist
from siem.rules import all_rules
from siem.storage import Storage

BASE = datetime(2026, 11, 20, 12, 0)


def _ingest_all(store, files):
    return {src: ingest_file(store, path, src, year=files.year)
            for src, path in (("auth", files.auth), ("web", files.web), ("app", files.app))}


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    d = tmp_path_factory.mktemp("attack")
    files = sample_data.generate(d / "logs", base_time=BASE)
    store = Storage(str(d / "siem.db"))
    results = _ingest_all(store, files)
    cfg = {"blocklist": load_blocklist(files.blocklist)}
    found, new = detect(store, cfg)
    return {"store": store, "files": files, "results": results, "cfg": cfg, "found": found, "new": new}


def _alerts(p, rule_id):
    return [a for a in p["store"].fetch_alerts() if a["rule_id"] == rule_id]


def test_every_log_line_is_understood(pipeline):
    for src, r in pipeline["results"].items():
        assert r.parsed > 0 and r.skipped == 0, src
        assert r.new == r.parsed, src


def test_all_rules_fire_on_the_demo_data(pipeline):
    fired = {a["rule_id"] for a in pipeline["store"].fetch_alerts()}
    assert fired == {r.id for r in all_rules()}


def test_expected_attackers_are_identified(pipeline):
    assert {a["src_ip"] for a in _alerts(pipeline, "AUTH-001")} == {"203.0.113.45"}
    assert {a["src_ip"] for a in _alerts(pipeline, "AUTH-002")} == {"198.51.100.23"}
    assert {a["username"] for a in _alerts(pipeline, "AUTH-003")} == {"admin"}
    assert {a["src_ip"] for a in _alerts(pipeline, "WEB-006")} == {"192.0.2.99"}
    assert {a["src_ip"] for a in _alerts(pipeline, "COR-001")} == {"203.0.113.45", "198.51.100.23"}
    assert [a["username"] for a in _alerts(pipeline, "COR-002")] == ["admin"]
    assert {a["src_ip"] for a in _alerts(pipeline, "TI-001")} == {"198.51.100.77"}


def test_insider_scenario_is_flagged_with_off_hours_severity(pipeline):
    export = _alerts(pipeline, "APP-001")
    role = _alerts(pipeline, "APP-002")
    assert len(export) == 1 and export[0]["username"] == "mallory"
    assert len(role) == 1 and role[0]["severity"] == "high"


def test_alerts_carry_evidence_and_mitre_mapping(pipeline):
    for a in pipeline["store"].fetch_alerts():
        assert a["evidence"], a["rule_id"]
        assert a["rule_id"] == "TI-001" or a["mitre"], a["rule_id"]


def test_reingesting_and_redetecting_creates_no_duplicates(pipeline):
    store, files = pipeline["store"], pipeline["files"]
    before = store.counts()
    again = _ingest_all(store, files)
    assert all(r.new == 0 for r in again.values())
    found, new = detect(store, pipeline["cfg"])
    assert new == 0 and found == pipeline["found"]
    assert store.counts() == before


def test_benign_traffic_alone_raises_no_alerts(tmp_path):
    """False-positive guard: a normal day of logs must stay quiet."""
    files = sample_data.generate(tmp_path / "logs", base_time=BASE, include_attacks=False)
    store = Storage(str(tmp_path / "benign.db"))
    _ingest_all(store, files)
    assert store.counts()["events"] > 500
    found, _ = detect(store, {"blocklist": load_blocklist(files.blocklist)})
    assert found == 0


def test_sample_generation_is_deterministic(tmp_path):
    a = sample_data.generate(tmp_path / "a", base_time=BASE, seed=3)
    b = sample_data.generate(tmp_path / "b", base_time=BASE, seed=3)
    for attr in ("auth", "web", "app"):
        assert open(getattr(a, attr)).read() == open(getattr(b, attr)).read()


# ------------------------------------------------------------ ingest edge cases ----
def test_unknown_source_is_rejected(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("hello\n")
    with pytest.raises(ValueError):
        ingest_file(Storage(str(tmp_path / "s.db")), str(f), "firewall")


def test_garbage_lines_are_counted_as_skipped_not_fatal(tmp_path):
    f = tmp_path / "access.log"
    good = '10.0.0.1 - - [22/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8"'
    f.write_text(f"{good}\nnot a log line\n\n\x00\x01binary junk\n{good.replace('10.0.0.1', '10.0.0.2')}\n")
    r = ingest_file(Storage(str(tmp_path / "s.db")), str(f), "web")
    assert (r.parsed, r.skipped, r.new) == (2, 2, 2)


def test_identical_lines_are_kept_but_reingest_is_idempotent(tmp_path):
    f = tmp_path / "access.log"
    line = '10.0.0.1 - - [22/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8"'
    f.write_text(f"{line}\n{line}\n")
    store = Storage(str(tmp_path / "s.db"))
    assert ingest_file(store, str(f), "web").new == 2  # two real requests in the same second
    assert ingest_file(store, str(f), "web").new == 0


def test_load_blocklist_ignores_comments_blank_lines_and_missing_files(tmp_path):
    f = tmp_path / "bl.txt"
    f.write_text("# header\n\n1.2.3.4\n  5.6.7.8  \n")
    assert load_blocklist(str(f)) == ["1.2.3.4", "5.6.7.8"]
    assert load_blocklist(str(tmp_path / "missing.txt")) == []
    assert load_blocklist(None) == []


def test_storage_roundtrip_preserves_fields(pipeline):
    events = pipeline["store"].fetch_events()
    web_evt = next(e for e in events if e.source == "web" and e.extra.get("status") == 500)
    assert web_evt.extra["path"].startswith("/products.php")
    assert web_evt.uid and web_evt.raw and web_evt.timestamp.year == 2026
    assert events == sorted(events, key=lambda e: e.timestamp)


# ------------------------------------------------------------------------ CLI ----
def test_cli_demo_then_alerts_and_rules(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    db = str(tmp_path / "cli.db")
    assert cli_main(["--db", db, "demo"]) == 0
    out = capsys.readouterr().out
    assert "Detection complete" in out and "203.0.113.45" in out

    assert cli_main(["--db", db, "alerts", "--min-severity", "critical"]) == 0
    crit = capsys.readouterr().out
    assert "CRITICAL" in crit and "MEDIUM" not in crit

    assert cli_main(["--db", db, "rules"]) == 0
    assert "COR-002" in capsys.readouterr().out

    assert cli_main(["--db", db, "reset"]) == 0
    assert Storage(db).counts() == {"events": 0, "alerts": 0}
