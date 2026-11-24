from datetime import datetime

from siem.parsers import parse_app_line, parse_auth_line, parse_web_line


# ------------------------------------------------------------------- auth.log --
def test_auth_failed_password_for_invalid_user():
    line = "Nov 22 10:15:32 srv01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"
    e = parse_auth_line(line, year=2026)
    assert e.source == "auth"
    assert e.event_type == "auth_failure"
    assert (e.src_ip, e.username, e.host) == ("203.0.113.5", "admin", "srv01")
    assert e.timestamp == datetime(2026, 11, 22, 10, 15, 32)
    assert e.raw == line


def test_auth_single_digit_day_is_space_padded_in_syslog():
    e = parse_auth_line("Nov  5 01:02:03 srv01 sshd[9]: Failed password for bob from 10.0.0.1 port 22 ssh2", year=2026)
    assert e.timestamp == datetime(2026, 11, 5, 1, 2, 3)


def test_auth_accepted_publickey():
    e = parse_auth_line("Nov 22 10:15:32 srv01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 5555 ssh2", year=2026)
    assert e.event_type == "auth_success"
    assert e.username == "alice" and e.extra["method"] == "publickey"


def test_auth_invalid_user_line_is_not_counted_as_a_failure():
    # sshd logs "Invalid user" AND "Failed password" for the same attempt; counting both would double the totals.
    e = parse_auth_line("Nov 22 10:15:32 srv01 sshd[1]: Invalid user test from 203.0.113.5 port 4242", year=2026)
    assert e.event_type == "auth_invalid_user"


def test_auth_sudo_command():
    e = parse_auth_line(
        "Nov 22 02:47:00 srv01 sudo[99]:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash", year=2026)
    assert e.event_type == "privilege_cmd"
    assert e.username == "admin"
    assert e.extra == {"command": "/bin/bash", "target_user": "root"}
    assert e.src_ip is None


def test_auth_ignores_unrelated_and_garbage_lines():
    assert parse_auth_line("Nov 22 10:00:00 srv01 cron[1]: (root) CMD (run-parts /etc/cron.hourly)", year=2026) is None
    assert parse_auth_line("this is not a log line", year=2026) is None
    assert parse_auth_line("", year=2026) is None


# ------------------------------------------------------------------- web log --
def test_web_line_converts_timezone_to_utc():
    line = ('203.0.113.5 - - [22/Nov/2026:10:15:32 +0530] "GET /products.php?id=1%27 HTTP/1.1" 200 512 "-" "sqlmap/1.7"')
    e = parse_web_line(line)
    assert e.timestamp == datetime(2026, 11, 22, 4, 45, 32)  # 10:15 at +05:30 is 04:45 UTC
    assert e.source == "web" and e.event_type == "http_request"
    assert e.src_ip == "203.0.113.5" and e.username is None
    assert e.extra["path"] == "/products.php?id=1%27"
    assert e.extra["status"] == 200 and e.extra["size"] == 512
    assert e.extra["user_agent"] == "sqlmap/1.7"


def test_web_line_authenticated_user_and_dash_size():
    e = parse_web_line('10.0.0.1 - bob [22/Nov/2026:10:15:32 +0000] "POST /login HTTP/1.1" 302 - "-" "curl/8"')
    assert e.username == "bob" and e.extra["size"] == 0 and e.extra["method"] == "POST"


def test_web_line_without_referrer_and_agent_still_parses():
    e = parse_web_line('10.0.0.1 - - [22/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 10')
    assert e is not None and e.extra["user_agent"] == ""


def test_web_garbage_is_skipped():
    assert parse_web_line("garbage") is None
    assert parse_web_line('1.2.3.4 - - [not a date] "GET / HTTP/1.1" 200 1') is None


# ------------------------------------------------------------------- app JSON --
def test_app_login_failed_maps_to_auth_failure():
    e = parse_app_line('{"ts":"2026-11-22T10:15:32Z","service":"webapp","event":"login_failed","user":"bob","ip":"10.0.0.9"}')
    assert e.event_type == "auth_failure" and e.source == "app"
    assert (e.username, e.src_ip, e.host) == ("bob", "10.0.0.9", "webapp")
    assert e.timestamp == datetime(2026, 11, 22, 10, 15, 32)


def test_app_custom_fields_go_to_extra_and_unknown_events_are_prefixed():
    e = parse_app_line('{"ts":"2026-11-22T10:00:00Z","event":"data_export","user":"m","ip":"1.1.1.1","records":25000,"dataset":"customers"}')
    assert e.event_type == "app_data_export"
    assert e.extra == {"records": 25000, "dataset": "customers"}


def test_app_timestamp_with_offset_is_normalized_to_utc():
    e = parse_app_line('{"ts":"2026-11-22T10:00:00+05:30","event":"login_success","user":"a","ip":"1.1.1.1"}')
    assert e.timestamp == datetime(2026, 11, 22, 4, 30, 0)


def test_app_bad_json_or_missing_fields_are_skipped():
    assert parse_app_line("{not json") is None
    assert parse_app_line('{"event":"login_failed"}') is None  # no ts
    assert parse_app_line('{"ts":"2026-11-22T10:00:00Z"}') is None  # no event
    assert parse_app_line('{"ts":"yesterday","event":"x"}') is None
    assert parse_app_line("plain text") is None
