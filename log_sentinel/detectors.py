"""Detection rules for SSH logins (LS-001 to LS-003) and the function that runs all rules."""
from datetime import timedelta

from .alerts import DEFAULTS, busiest_window, by_ip, make_alert
from .web_detectors import web_attacks, web_enumeration


def ssh_brute_force(auth, threshold, window):
    """LS-001: one IP fails to log in at least `threshold` times within `window`."""
    alerts = []
    for ip, failures in by_ip(e for e in auth if not e.success).items():
        burst = busiest_window(failures, window)
        if len(burst) >= threshold:
            alerts.append(make_alert("LS-001", ip, burst,
                                 f"{len(burst)} failed logins within {window}s"))
    return alerts


def password_spraying(auth, threshold, window):
    """LS-002: one IP fails against at least `threshold` different usernames."""
    alerts = []
    for ip, failures in by_ip(e for e in auth if not e.success).items():
        burst = busiest_window(failures, window, key=lambda e: e.user)
        users = sorted({e.user for e in burst})
        if len(users) >= threshold:
            alerts.append(make_alert("LS-002", ip, burst,
                                 f"{len(users)} usernames tried: {', '.join(users)}"))
    return alerts


def success_after_failures(auth, threshold, window):
    """LS-003: a login succeeds from an IP that failed `threshold`+ times just before."""
    alerts = []
    for ip, events in by_ip(auth).items():
        for login in (e for e in events if e.success):
            gap = timedelta(seconds=window)
            failures = [e for e in events
                        if not e.success and timedelta(0) <= login.ts - e.ts <= gap]
            if len(failures) >= threshold:
                alerts.append(make_alert("LS-003", ip, failures + [login],
                                     f"login as {login.user} after {len(failures)} failures"))
                break  # one alert per IP is enough for triage
    return alerts


def run_all(auth, web, settings=None):
    """Run every rule and return the alerts, most severe first."""
    settings = settings or DEFAULTS
    alerts = (ssh_brute_force(auth, *settings["LS-001"])
              + password_spraying(auth, *settings["LS-002"])
              + success_after_failures(auth, *settings["LS-003"])
              + web_attacks(web, *settings["LS-004"])
              + web_enumeration(web, *settings["LS-005"]))
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(alerts, key=lambda a: (rank[a.severity], a.rule_id, a.source_ip))
