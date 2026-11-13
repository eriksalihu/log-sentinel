"""The Alert record, the rule catalogue and helpers shared by every detector."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

# rule id: (title, severity, MITRE ATT&CK technique)
RULES = {
    "LS-001": ("SSH brute force", "medium", "T1110.001"),
    "LS-002": ("Password spraying", "medium", "T1110.003"),
    "LS-003": ("Login success after failures", "high", "T1078"),
    "LS-004": ("Web attack pattern", "medium", "T1190"),
    "LS-005": ("Web enumeration", "low", "T1595"),
}

# rule id: [threshold, time window in seconds]. The CLI can override both.
DEFAULTS = {
    "LS-001": [5, 300],   # failed logins from one IP
    "LS-002": [4, 300],   # different usernames failed by one IP
    "LS-003": [3, 300],   # failures shortly before a success
    "LS-004": [1, 300],   # requests matching an attack signature
    "LS-005": [15, 60],   # 404 responses to one IP
}


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    attack_id: str
    source_ip: str
    first_seen: str
    last_seen: str
    evidence_count: int
    detail: str


def make_alert(rule_id, ip, events, detail):
    """Build an Alert whose time range and count come from `events`."""
    times = sorted(e.ts for e in events)
    return Alert(rule_id, *RULES[rule_id], ip, times[0].isoformat(sep=" "),
                 times[-1].isoformat(sep=" "), len(events), detail)


def by_ip(events):
    groups = defaultdict(list)
    for event in events:
        groups[event.ip].append(event)
    return groups


def busiest_window(events, seconds, key=id):
    """Return the events inside the `seconds`-long window with the most distinct keys.

    A window slides over the time-sorted events: `end` moves forward one event
    at a time and `start` catches up whenever the two are more than `seconds`
    apart. With the default key every event counts once; with
    key=lambda e: e.user the window with the most different usernames wins.
    """
    events = sorted(events, key=lambda e: e.ts)
    best, start = [], 0
    for end in range(len(events)):
        while events[end].ts - events[start].ts > timedelta(seconds=seconds):
            start += 1
        current = events[start:end + 1]
        if len({key(e) for e in current}) > len({key(e) for e in best}):
            best = current
    return best
