"""Detection rules for web server access logs (LS-004 and LS-005)."""
import re
from urllib.parse import unquote_plus

from .alerts import busiest_window, by_ip, make_alert

SIGNATURES = {
    "SQL injection": re.compile(
        r"union\s+(all\s+)?select|'\s*or\s+'?1'?\s*=\s*'?1|information_schema|sleep\(\d+\)", re.I),
    "XSS": re.compile(r"<script|onerror\s*=|javascript:", re.I),
    "path traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd", re.I),
}
SCANNERS = re.compile(r"nikto|sqlmap|nmap|gobuster|dirbuster|wfuzz|nuclei|masscan|zgrab", re.I)



def classify(path):
    """Return the names of the attack signatures found in a request path."""
    # Decode twice so that double-encoded payloads (%253Cscript) are also caught.
    decoded = unquote_plus(unquote_plus(path))
    return [name for name, pattern in SIGNATURES.items() if pattern.search(decoded)]


def web_attacks(web, threshold, window):
    """LS-004: one IP sends `threshold`+ requests that match an attack signature."""
    alerts = []
    for ip, requests in by_ip(e for e in web if classify(e.path)).items():
        burst = busiest_window(requests, window)
        if len(burst) >= threshold:
            kinds = sorted({kind for e in burst for kind in classify(e.path)})
            alerts.append(make_alert("LS-004", ip, burst, "signatures: " + ", ".join(kinds)))
    return alerts


def web_enumeration(web, threshold, window):
    """LS-005: a known scanner user agent, or `threshold`+ 404s within `window`."""
    alerts = []
    for ip, requests in by_ip(web).items():
        scans = [e for e in requests if SCANNERS.search(e.agent)]
        burst = busiest_window([e for e in requests if e.status == 404], window)
        if scans:
            alerts.append(make_alert("LS-005", ip, scans, f"scanner user agent: {scans[0].agent}"))
        elif len(burst) >= threshold:
            alerts.append(make_alert("LS-005", ip, burst,
                                 f"{len(burst)} 404 responses within {window}s"))
    return alerts
