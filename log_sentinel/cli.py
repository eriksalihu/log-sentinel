"""Command-line entry point: read the logs, run the rules, print the report."""
import argparse
import copy
from datetime import datetime

from . import detectors, parsers, report


def _read(path):
    # errors="replace" keeps one odd byte in a log from stopping the analysis.
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.readlines()


def _settings(thresholds, windows):
    """Apply --threshold and --window overrides (RULE=NUMBER) to the defaults."""
    settings = copy.deepcopy(detectors.DEFAULTS)
    for position, overrides in ((0, thresholds), (1, windows)):
        for item in overrides:
            rule, _, number = item.partition("=")
            if rule not in settings or not number.isdigit():
                raise SystemExit(f"error: expected RULE=NUMBER with a known rule id, got '{item}'")
            settings[rule][position] = int(number)
    return settings


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="log_sentinel",
        description="Report suspicious activity in an auth.log and a web access log.")
    parser.add_argument("--auth", metavar="FILE", help="Linux auth.log with sshd entries")
    parser.add_argument("--web", metavar="FILE", help="nginx or Apache access log")
    parser.add_argument("--json", action="store_true", help="print alerts as JSON")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year for syslog timestamps that have none (default: this year)")
    parser.add_argument("--threshold", action="append", default=[], metavar="RULE=N",
                        help="override a rule's threshold, e.g. LS-001=10 (repeatable)")
    parser.add_argument("--window", action="append", default=[], metavar="RULE=SECONDS",
                        help="override a rule's time window, e.g. LS-001=600 (repeatable)")
    args = parser.parse_args(argv)
    if not args.auth and not args.web:
        parser.error("give at least one of --auth or --web")

    settings = _settings(args.threshold, args.window)
    auth = parsers.parse_auth_log(_read(args.auth), args.year) if args.auth else []
    web = parsers.parse_access_log(_read(args.web)) if args.web else []
    alerts = detectors.run_all(auth, web, settings)
    print(report.to_json(alerts) if args.json else report.to_table(alerts))
    return 0  # alerts are findings, not errors, so the exit code stays 0
