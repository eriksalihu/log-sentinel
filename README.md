# log-sentinel

A small Python command-line tool that reads a Linux `auth.log` and an nginx or Apache access log and reports SSH brute force, password spraying, suspicious logins, web attack patterns and web enumeration.

[![CI](https://github.com/eriksalihu/log-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/eriksalihu/log-sentinel/actions/workflows/ci.yml)

## Why a SOC analyst would use it

When an alert or a ticket points at a Linux server, the first questions are usually "who was hammering SSH?", "did anyone get in?" and "what was thrown at the web server?". log-sentinel answers those from the two log files that are almost always there, without a SIEM, an agent or any installation. Every alert names the source IP, the time range, the amount of evidence and the MITRE ATT&CK technique, so it can go straight into a ticket.

## Features

- Five detection rules, each with its own threshold and time window that can be changed from the command line
- Readable table by default, `--json` for scripts and tickets
- Reads classic syslog timestamps and ISO 8601 timestamps in `auth.log`, and the common and combined access log formats
- Python standard library only: no third-party runtime dependencies
- Synthetic sample logs in `samples/` and a pytest suite with a firing and a non-firing case for every rule

## Quick start

Requires Python 3.9 or newer.

```bash
git clone https://github.com/eriksalihu/log-sentinel.git
cd log-sentinel
python -m log_sentinel --auth samples/auth.log --web samples/access.log --year 2026
```

Other useful calls:

```bash
# JSON output
python -m log_sentinel --auth samples/auth.log --web samples/access.log --year 2026 --json

# Only one log, with a stricter brute-force rule: 10 failures within 10 minutes
python -m log_sentinel --auth /var/log/auth.log --threshold LS-001=10 --window LS-001=600
```

`--year` is only needed for classic syslog timestamps, which do not contain a year. It defaults to the current year.

## Example output

Copied from the job summary of this repository's CI run on the files in `samples/`:

```text
SEVERITY  RULE    ATT&CK     SOURCE IP       FIRST SEEN           LAST SEEN            COUNT  DETAIL
--------  ------  ---------  --------------  -------------------  -------------------  -----  --------------------------------------------------------------------------------
high      LS-003  T1078      192.0.2.77      2026-11-10 02:58:00  2026-11-10 02:59:01  5      login as arta after 4 failures
medium    LS-001  T1110.001  198.51.100.23   2026-11-10 02:31:00  2026-11-10 02:31:55  6      6 failed logins within 300s
medium    LS-001  T1110.001  203.0.113.50    2026-11-10 02:00:14  2026-11-10 02:01:03  8      8 failed logins within 300s
medium    LS-002  T1110.003  198.51.100.23   2026-11-10 02:31:00  2026-11-10 02:31:55  6      6 usernames tried: admin, backup, oracle, postgres, test, ubuntu
medium    LS-004  T1190      203.0.113.99    2026-11-10 09:07:00  2026-11-10 09:08:08  5      signatures: SQL injection, XSS, path traversal
low       LS-005  T1595      198.51.100.200  2026-11-10 09:15:00  2026-11-10 09:15:30  16     16 404 responses within 60s
low       LS-005  T1595      198.51.100.77   2026-11-10 09:24:00  2026-11-10 09:24:02  3      scanner user agent: Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)

7 alert(s) from 6 source IP(s)
```

With `--json`, each alert is an object with the fields `rule_id`, `title`, `severity`, `attack_id`, `source_ip`, `first_seen`, `last_seen`, `evidence_count` and `detail`.

## How each detection works

| Rule | Detection | Default | How it works |
|---|---|---|---|
| LS-001 | SSH brute force | 5 failures in 300 s | Counts failed SSH logins per source IP in a sliding time window. |
| LS-002 | Password spraying | 4 usernames in 300 s | Counts the different usernames one source IP failed against in a sliding window. |
| LS-003 | Login success after failures | 3 failures in the 300 s before | Flags a successful login from an IP that failed several times shortly before it. |
| LS-004 | Web attack pattern | 1 request in 300 s | URL-decodes each request path twice and matches SQL injection, XSS and path traversal signatures. |
| LS-005 | Web enumeration | 15 responses with status 404 in 60 s | Flags a burst of 404 responses to one IP, or any request with a known scanner user agent. |

The full walkthrough, with the reasoning behind every threshold and the likely false positives, is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## MITRE ATT&CK mapping

| Rule | Technique | Name |
|---|---|---|
| LS-001 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |
| LS-002 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying |
| LS-003 | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |
| LS-004 | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| LS-005 | [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning |

## Limitations

- It works on log files after the fact. It is not a real-time monitor and it does not block anything.
- Everything is grouped by source IP, so an attack spread over many addresses stays under the thresholds, and many users behind one NAT address can look like one noisy source.
- The web signatures are a short list of well-known patterns. They show that someone tried an attack, not that it worked, and an attacker who obfuscates the payload can avoid them.
- Only sshd password and public-key results are read from `auth.log`. Other services such as sudo or su are ignored.
- Timestamps are compared as written in each log, without converting time zones.
- The logs are loaded into memory, which is fine for a day of logs from one server but not for very large files.

## Next steps

- Read rotated and gzip-compressed logs
- Add sudo and su events to the auth rules
- Add an allowlist for known-good IP addresses such as monitoring systems
- Add CSV output for spreadsheets

## License

[MIT](LICENSE)
