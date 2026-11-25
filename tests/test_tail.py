"""Tests for the live-file watcher and the line-by-line ingestion built on top of it."""
from siem.engine import detect, ingest_lines
from siem.storage import Storage
from siem.tail import FileTailer


def append(path, text):
    with open(path, "ab") as fh:  # binary + explicit bytes so tests behave the same on every OS
        fh.write(text.encode())


def texts(lines):
    return [nl.text for nl in lines]


def failed(sec, ip="203.0.113.9", user="root"):
    return f"Nov 24 10:00:{sec:02d} srv01 sshd[1]: Failed password for {user} from {ip} port 22 ssh2\n"


# ---------------------------------------------------------------- the watcher ----
def test_only_lines_written_after_start_are_reported(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("old line 1\nold line 2\n")
    t = FileTailer(f)
    assert t.poll() == []                      # existing content is ignored
    append(f, "new line\n")
    assert texts(t.poll()) == ["new line"]
    assert t.poll() == []                      # nothing new => nothing returned twice


def test_from_start_also_reports_existing_lines(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("a\nb\n")
    assert texts(FileTailer(f, from_start=True).poll()) == ["a", "b"]


def test_half_written_line_waits_until_it_is_finished(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("")
    t = FileTailer(f)
    append(f, "abc")
    assert t.poll() == []                      # no newline yet: not a complete line
    append(f, "def\n")
    assert texts(t.poll()) == ["abcdef"]


def test_several_lines_in_one_poll_keep_their_order_and_byte_offsets(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("")
    t = FileTailer(f)
    append(f, "aa\nbbb\ncccc\n")
    got = t.poll()
    assert texts(got) == ["aa", "bbb", "cccc"]
    assert [nl.offset for nl in got] == [0, 3, 7]


def test_windows_line_endings_and_blank_lines(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("")
    t = FileTailer(f)
    append(f, "one\r\n\r\ntwo\r\n")
    assert texts(t.poll()) == ["one", "two"]


def test_file_that_is_emptied_is_read_again_from_the_top(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("")
    t = FileTailer(f)
    append(f, "first line of the day\n")
    assert len(t.poll()) == 1
    f.write_text("fresh\n")                    # shorter than before => file was rotated/truncated
    assert texts(t.poll()) == ["fresh"]


def test_file_that_does_not_exist_yet_is_picked_up_when_created(tmp_path):
    f = tmp_path / "later.log"
    t = FileTailer(f)
    assert t.poll() == []
    f.write_text("hello\n")
    assert texts(t.poll()) == ["hello"]


def test_file_that_disappears_does_not_crash_the_watcher(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("x\n")
    t = FileTailer(f, from_start=True)
    assert len(t.poll()) == 1
    f.unlink()
    assert t.poll() == []


def test_bad_bytes_do_not_crash_the_watcher(tmp_path):
    f = tmp_path / "live.log"
    f.write_text("")
    t = FileTailer(f)
    with open(f, "ab") as fh:
        fh.write(b"caf\xe9 \xff\xfe broken\n")  # not valid UTF-8
    assert len(t.poll()) == 1


# ------------------------------------------------------- saving the new lines ----
def test_ingest_lines_stores_events_and_counts_unreadable_lines(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("")
    t, store = FileTailer(f), Storage(str(tmp_path / "s.db"))
    append(f, failed(1) + "this is not a log line\n" + failed(2))
    r = ingest_lines(store, t.poll(), "auth", str(f), year=2026)
    assert (r.parsed, r.skipped, r.new) == (2, 1, 2)
    assert store.counts()["events"] == 2


def test_rereading_the_same_lines_adds_nothing(tmp_path):
    """Restarting the watcher with --from-start must not double-count anything."""
    f = tmp_path / "auth.log"
    f.write_text(failed(1) + failed(2) + failed(3))
    store = Storage(str(tmp_path / "s.db"))
    first = ingest_lines(store, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)
    again = ingest_lines(store, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)
    assert first.new == 3 and again.new == 0
    assert store.counts()["events"] == 3


def test_identical_lines_at_different_positions_are_both_kept(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(failed(1) + failed(1))        # two real attempts logged in the same second
    store = Storage(str(tmp_path / "s.db"))
    r = ingest_lines(store, FileTailer(f, from_start=True).poll(), "auth", str(f), year=2026)
    assert r.new == 2


def test_unknown_source_is_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        ingest_lines(Storage(str(tmp_path / "s.db")), [], "firewall", str(tmp_path / "x.log"))


def test_attack_written_line_by_line_is_detected_live(tmp_path):
    """The whole idea in one test: lines trickle in, and the brute-force rule fires at the 5th."""
    f = tmp_path / "auth.log"
    f.write_text("")
    t, store = FileTailer(f), Storage(str(tmp_path / "s.db"))
    for sec in range(1, 5):                    # 4 failures so far: still quiet
        append(f, failed(sec * 3))
        ingest_lines(store, t.poll(), "auth", str(f), year=2026)
    found, _ = detect(store)
    assert found == 0
    append(f, failed(15))                      # the 5th failure arrives
    ingest_lines(store, t.poll(), "auth", str(f), year=2026)
    found, new = detect(store)
    assert found == 1 and new == 1
    assert store.fetch_alerts()[0]["rule_id"] == "AUTH-001"
