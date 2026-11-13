"""Format alerts as a plain-text table or as JSON."""
import json
from dataclasses import asdict

COLUMNS = [
    ("SEVERITY", "severity"), ("RULE", "rule_id"), ("ATT&CK", "attack_id"),
    ("SOURCE IP", "source_ip"), ("FIRST SEEN", "first_seen"),
    ("LAST SEEN", "last_seen"), ("COUNT", "evidence_count"), ("DETAIL", "detail"),
]


def to_json(alerts):
    """Return the alerts as a JSON array, one object per alert."""
    return json.dumps([asdict(alert) for alert in alerts], indent=2)


def to_table(alerts):
    """Return the alerts as an aligned text table with a one-line summary."""
    if not alerts:
        return "No suspicious activity found."
    rows = [[header for header, _ in COLUMNS]]
    for alert in alerts:
        rows.append([str(getattr(alert, field)) for _, field in COLUMNS])
    # Each column is as wide as its longest cell.
    widths = [max(len(row[i]) for row in rows) for i in range(len(COLUMNS))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
             for row in rows]
    lines.insert(1, "  ".join("-" * width for width in widths))
    lines.append("")
    lines.append(f"{len(alerts)} alert(s) from {len({a.source_ip for a in alerts})} source IP(s)")
    return "\n".join(lines)
