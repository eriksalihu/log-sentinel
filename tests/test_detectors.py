"""Each rule gets one case that must raise an alert and one that must stay quiet."""
from datetime import datetime, timedelta

from log_sentinel import detectors, web_detectors
from log_sentinel.parsers import AuthEvent, WebEvent

START = datetime(2026, 11, 10, 2, 0, 0)
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"


def auth(second, user="root", success=False, ip="203.0.113.50"):
    return AuthEvent(START + timedelta(seconds=second), ip, user, success)


def web(second, path="/", status=200, agent=BROWSER, ip="203.0.113.99"):
    return WebEvent(START + timedelta(seconds=second), ip, "GET", path, status, agent)


def test_brute_force_fires_on_five_failures_in_window():
    alerts = detectors.ssh_brute_force([auth(i * 10) for i in range(5)], 5, 300)
    assert [(a.rule_id, a.source_ip, a.evidence_count) for a in alerts] == [("LS-001", "203.0.113.50", 5)]


def test_brute_force_quiet_when_failures_are_spread_out():
    # Five failures, but ten minutes apart: never five inside one 300 s window.
    assert detectors.ssh_brute_force([auth(i * 600) for i in range(5)], 5, 300) == []


def test_spraying_fires_on_many_usernames():
    events = [auth(i, user) for i, user in enumerate(["admin", "test", "oracle", "backup"])]
    alerts = detectors.password_spraying(events, 4, 300)
    assert len(alerts) == 1 and alerts[0].attack_id == "T1110.003"


def test_spraying_quiet_when_one_username_is_repeated():
    assert detectors.password_spraying([auth(i, "root") for i in range(10)], 4, 300) == []


def test_success_after_failures_fires():
    events = [auth(0, "arta"), auth(5, "arta"), auth(10, "arta"), auth(20, "arta", success=True)]
    alerts = detectors.success_after_failures(events, 3, 300)
    assert len(alerts) == 1 and alerts[0].severity == "high"


def test_success_after_failures_quiet_for_a_single_typo():
    events = [auth(0, "dren"), auth(8, "dren", success=True)]
    assert detectors.success_after_failures(events, 3, 300) == []


def test_web_attacks_fire_on_each_signature_family():
    events = [web(0, "/p?id=1%20UNION%20SELECT%20a,b"), web(1, "/s?q=%3Cscript%3E"),
              web(2, "/d?file=..%252f..%252fetc%252fpasswd")]
    alerts = web_detectors.web_attacks(events, 1, 300)
    assert alerts[0].detail == "signatures: SQL injection, XSS, path traversal"


def test_web_attacks_quiet_on_normal_requests():
    events = [web(0, "/products?id=42"), web(1, "/search?q=select+a+union+card")]
    assert web_detectors.web_attacks(events, 1, 300) == []


def test_enumeration_fires_on_404_burst_and_on_scanner_agent():
    burst = [web(i, f"/guess{i}", 404) for i in range(15)]
    scanner = [web(0, "/", agent="Mozilla/5.00 (Nikto/2.5.0)", ip="198.51.100.77")]
    alerts = web_detectors.web_enumeration(burst + scanner, 15, 60)
    assert sorted(a.source_ip for a in alerts) == ["198.51.100.77", "203.0.113.99"]


def test_enumeration_quiet_on_a_few_404s():
    assert web_detectors.web_enumeration([web(i, "/x", 404) for i in range(3)], 15, 60) == []
