"""Command-line entry point: sshlab <logfile>."""

from __future__ import annotations

import argparse
from datetime import timedelta

from sshlab.parser import parse_file
from sshlab.report import write_report
from sshlab.rules import THRESHOLD, detect_brute_force


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect attacks in an SSH auth log.")
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    parser.add_argument("--threshold", type=int, default=THRESHOLD,
                        help=f"failures per window that raise an alert (default {THRESHOLD})")
    parser.add_argument("--output", default="report.json", help="where to write the JSON report")
    args = parser.parse_args()

    events, skipped = parse_file(args.logfile)
    alerts = detect_brute_force(events, timedelta(minutes=args.window), args.threshold)
    write_report(alerts, args.output, args.logfile, skipped)

    print(f"{len(events)} events parsed, {skipped} lines skipped, {len(alerts)} alerts")
    for alert in alerts:
        print(f"  [{alert.severity:8}] {alert.src_ip:16} peak {alert.peak_in_window:3} "
              f"in {args.window} min, {alert.attempts:3} total, {len(alert.users)} usernames")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
