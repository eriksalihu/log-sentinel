"""Parser tests, plus an end-to-end run of the CLI on the bundled samples."""
import json

from log_sentinel import cli, parsers

FAILED = "Nov 10 02:00:14 web01 sshd[2100]: Failed password for invalid user admin from 203.0.113.50 port 41000 ssh2"
ACCEPTED = "2026-11-10T02:12:09.120394+01:00 web01 sshd[2201]: Accepted password for dren from 192.0.2.10 port 51514 ssh2"
REQUEST = '203.0.113.99 - - [10/Nov/2026:09:07:00 +0100] "GET /a?b=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'


def test_auth_parser_reads_failures_and_successes_in_both_time_formats():
    failed, accepted = parsers.parse_auth_log([FAILED, ACCEPTED], 2026)
    assert (failed.user, failed.ip, failed.success, failed.ts.year) == ("admin", "203.0.113.50", False, 2026)
    assert (accepted.user, accepted.success, accepted.ts.hour) == ("dren", True, 2)


def test_auth_parser_ignores_lines_that_are_not_login_results():
    lines = ["Nov 10 02:00:13 web01 sshd[2100]: Invalid user admin from 203.0.113.50 port 41000",
             "Nov 10 02:00:15 web01 CRON[2110]: pam_unix(cron:session): session opened for user root"]
    assert parsers.parse_auth_log(lines, 2026) == []


def test_access_parser_reads_combined_format_and_skips_garbage():
    events = parsers.parse_access_log([REQUEST, "not a log line"])
    assert len(events) == 1
    assert (events[0].ip, events[0].path, events[0].status, events[0].agent) == (
        "203.0.113.99", "/a?b=1", 200, "Mozilla/5.0")


def test_cli_json_on_samples_reports_every_rule(capsys):
    code = cli.main(["--auth", "samples/auth.log", "--web", "samples/access.log",
                     "--year", "2026", "--json"])
    alerts = json.loads(capsys.readouterr().out)
    assert code == 0
    assert {a["rule_id"] for a in alerts} == {"LS-001", "LS-002", "LS-003", "LS-004", "LS-005"}
    # The benign users in the samples must not show up as sources.
    assert not {"192.0.2.10", "192.0.2.11", "192.0.2.12"} & {a["source_ip"] for a in alerts}


def test_cli_threshold_override_silences_a_rule(capsys):
    cli.main(["--auth", "samples/auth.log", "--year", "2026", "--json", "--threshold", "LS-001=50"])
    assert "LS-001" not in {a["rule_id"] for a in json.loads(capsys.readouterr().out)}
