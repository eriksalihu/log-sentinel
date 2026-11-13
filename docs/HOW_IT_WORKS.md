# How log-sentinel works

This document explains the design in plain language: how a log line becomes an alert, what every rule looks for, why the thresholds are what they are, and where each rule can be wrong.

## The pipeline

```
log files -> parsers.py -> events -> detectors.py / web_detectors.py -> alerts -> report.py -> table or JSON
```

1. **Parse.** `parsers.py` reads each line with a regular expression and keeps only the fields the rules need. An SSH login attempt becomes an `AuthEvent` (time, source IP, username, success or failure). An HTTP request becomes a `WebEvent` (time, source IP, method, path, status code, user agent). Lines that do not match are skipped, so a strange line never stops the run.
2. **Detect.** Each rule is one small function that takes a list of events, a threshold and a time window, and returns a list of `Alert` records. `detectors.run_all` calls the five rules and sorts the result with the most severe alerts first.
3. **Report.** `report.py` prints the alerts as an aligned table or as JSON. `cli.py` connects the three steps and handles the command-line options.

`alerts.py` holds what the rules share: the `Alert` record, the rule catalogue (title, severity and ATT&CK technique for each rule id), the default thresholds, and the sliding-window helper described next.

## The sliding window

Most rules ask the same question: "did one IP do this at least N times within S seconds?" Counting all events in the file would be wrong, because 5 failed logins spread over a whole day are normal and 5 within one minute are not.

`busiest_window` answers the question. It sorts one IP's events by time and moves a window across them. The `end` of the window steps forward one event at a time. Whenever the first and last event in the window are more than S seconds apart, the `start` moves forward until they fit again. The function remembers the fullest window it saw and returns its events. The rule then only has to compare the size of that window with the threshold.

The helper takes an optional `key`. By default every event counts once. Password spraying passes `key=lambda e: e.user`, so the window with the most *different usernames* wins rather than the window with the most events.

The alert's first-seen time, last-seen time and evidence count all come from the events in that window.

## About the timestamps

Classic syslog lines look like `Nov 10 02:00:14` and contain no year. The parser adds the year given with `--year` (the current year by default). Newer systems write ISO 8601 timestamps such as `2026-11-10T02:00:14+01:00`, which the parser reads directly. Time zone offsets are dropped and the local time is kept as written.

sshd writes two lines for a failed login with an unknown username: `Invalid user admin from ...` and `Failed password for invalid user admin from ...`. The parser only uses the second one, otherwise every such attempt would be counted twice.

## The rules

### LS-001 SSH brute force (T1110.001, medium)

- **Looks for:** at least 5 failed SSH logins from one IP within 300 seconds.
- **Why these numbers:** a person who mistypes a password usually gets it right within two or three tries. Five failures in five minutes is more than a typo but low enough to catch slow automated guessing.
- **Likely false positives:** a script or backup job with an outdated password that retries in a loop; several users behind one NAT address who all mistype around the same time; a user who has really forgotten the password.
- **Can miss:** guessing that stays under 5 attempts per 5 minutes, or that is spread over many source addresses.

### LS-002 Password spraying (T1110.003, medium)

- **Looks for:** one IP failing against at least 4 different usernames within 300 seconds.
- **Why these numbers:** one person normally logs in with one or two accounts. Four different names from one address in five minutes means someone is trying a list of names.
- **Likely false positives:** a shared jump host or NAT gateway used by many people; an administrator testing several service accounts after a password change.
- **Note:** an IP that sprays also produces enough failures for LS-001, so it usually appears under both rules. That is intended: the two alerts describe the same activity from two angles, and the LS-002 detail lists the usernames that were tried.

### LS-003 Login success after failures (T1078, high)

- **Looks for:** a successful login from an IP that had at least 3 failed logins in the 300 seconds before it. The failures can be for any username.
- **Why it is high severity:** the other auth rules show an attempt. This one shows that the attempt may have worked, which is the difference between noise and a possible compromise.
- **Why these numbers:** the threshold is lower than for LS-001 because a success after even a few failures deserves a look.
- **Likely false positives:** a real user who mistypes the password three times and then gets it right. This is the most common cause, so the first triage step is to ask the account owner.
- **Output:** one alert per IP. The evidence count is the number of failures plus the successful login.

### LS-004 Web attack pattern (T1190, medium)

- **Looks for:** requests whose path or query string matches a signature, after URL-decoding:
  - SQL injection: `union select`, `' or '1'='1`, `information_schema`, `sleep(N)`
  - XSS: `<script`, `onerror=`, `javascript:`
  - Path traversal: `../`, `..\`, `/etc/passwd`
- **Why decode twice:** attackers encode payloads to slip past filters. `%3Cscript` decodes to `<script` in one step, but `%253Cscript` needs two. Decoding twice catches both.
- **Why threshold 1:** a single request with `union select` in it is not normal browsing, so one match is enough.
- **Likely false positives:** an authorised vulnerability scan or penetration test; a search for text that contains one of the patterns, for example a programming forum where people search for `<script`.
- **Important:** a match means someone *tried*. To see whether it worked, look at the status code and response size of those requests and at the application logs.
- **Can miss:** payloads sent in a POST body (access logs only record the URL) and payloads that are obfuscated beyond these simple patterns.

### LS-005 Web enumeration (T1595, low)

- **Looks for:** either of two things from one IP:
  - any request whose user agent names a known scanner (nikto, sqlmap, nmap, gobuster, dirbuster, wfuzz, nuclei, masscan, zgrab), or
  - at least 15 responses with status 404 within 60 seconds.
- **Why these numbers:** a normal visitor hits a 404 now and then. Fifteen in a minute means a tool is guessing file and directory names from a wordlist.
- **Why it is low severity:** scanning of public web servers happens constantly. It matters mostly as context, for example when the same IP also appears under LS-004.
- **Likely false positives:** a search-engine crawler following old links after a site redesign; a broken page that requests many missing images; your own monitoring or an authorised scan.
- **Can miss:** scanners that change their user agent and scan slowly.
- **Output:** one alert per IP. If a scanner user agent was seen, that is reported; otherwise the 404 burst is.

## Changing thresholds and windows

Every rule can be tuned without editing code:

```bash
python -m log_sentinel --auth auth.log --threshold LS-001=10 --window LS-001=600
```

Both options can be repeated. `cli.py` copies the defaults from `alerts.py`, applies the overrides, and passes the result to `detectors.run_all`.

## The sample data

`samples/auth.log` and `samples/access.log` are synthetic. They use the reserved documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 and the reserved domain example.com. They contain one scenario for every rule, plus normal activity that must not raise an alert: a user who mistypes a password once, a key-based login, ordinary browsing and a single 404.

## The tests

`tests/test_detectors.py` has two tests per rule: one input that must raise the alert and one similar input that must not, such as five failures inside the window against five failures that are ten minutes apart. `tests/test_parsers_cli.py` checks the parsers and runs the whole tool on the sample files.

## Exit code

The tool exits with 0 when it ran correctly, whether or not it found alerts. An alert is a finding, not an error, so CI can run the tool on the samples without failing the build.
