"""Turn raw log lines into small event records that the detectors can reason about."""
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AuthEvent:
    """One SSH login attempt taken from auth.log."""
    ts: datetime
    ip: str
    user: str
    success: bool


@dataclass
class WebEvent:
    """One HTTP request taken from an nginx or Apache access log."""
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    agent: str


# Matches "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2"
# and "Accepted publickey for deploy from 192.0.2.1 port 22 ssh2".
# The separate "Invalid user ..." lines are ignored on purpose: sshd also logs a
# "Failed password for invalid user ..." line for the same attempt, so counting
# both would double every failure.
_SSH = re.compile(
    r"sshd(?:\[\d+\])?: (?P<result>Failed|Accepted) \S+ for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)

# Common and combined log format. The referrer and user agent are optional.
_WEB = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?'
)


def _auth_time(line, year):
    """Read the timestamp at the start of a syslog line.

    Newer systems write ISO 8601 ("2026-11-12T03:14:07+01:00"). The classic
    format ("Nov 12 03:14:07") has no year, so the caller has to supply one.
    """
    first_word = line.split(" ", 1)[0]
    if first_word[:4].isdigit():
        return datetime.fromisoformat(first_word).replace(tzinfo=None)
    return datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")


def parse_auth_log(lines, year):
    """Return an AuthEvent for every sshd login success or failure in `lines`."""
    events = []
    for line in lines:
        match = _SSH.search(line)
        if not match:
            continue
        try:
            ts = _auth_time(line, year)
        except ValueError:
            continue  # unreadable timestamp: skip the line rather than crash
        events.append(AuthEvent(ts, match["ip"], match["user"], match["result"] == "Accepted"))
    return events


def parse_access_log(lines):
    """Return a WebEvent for every well-formed request line in `lines`."""
    events = []
    for line in lines:
        match = _WEB.match(line)
        if not match:
            continue
        try:
            ts = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except ValueError:
            continue
        events.append(WebEvent(ts, match["ip"], match["method"], match["path"],
                               int(match["status"]), match["agent"] or ""))
    return events
