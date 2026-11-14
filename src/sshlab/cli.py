"""Command-line entry point: sshlab <logfile>."""

from __future__ import annotations

import argparse
from datetime import timedelta

from sshlab import store
from sshlab.parser import parse_file
from sshlab.report import write_report
from sshlab.rules import THRESHOLD, run_all_rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect attacks in an SSH auth log.")
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    parser.add_argument("--threshold", type=int, default=THRESHOLD,
                        help=f"failures per window that raise an alert (default {THRESHOLD})")
    parser.add_argument("--output", default="report.json", help="where to write the JSON report")
    parser.add_argument("--db", default="sshlab.db", help="SQLite database file (default sshlab.db)")
    args = parser.parse_args()

    events, skipped = parse_file(args.logfile)
    conn = store.connect(args.db)
    new_events = store.save_events(conn, events)

    # Detect on everything stored so far, not just this file.
    all_events = store.load_events(conn)
    alerts = run_all_rules(all_events, timedelta(minutes=args.window), args.threshold)
    store.save_alerts(conn, alerts)
    write_report(alerts, args.output, args.logfile, skipped)

    print(f"{len(events)} events parsed, {skipped} lines skipped")
    print(f"{new_events} new events stored, {len(events) - new_events} already in the database")
    print(f"Database now holds {store.count_rows(conn, 'events')} events "
          f"and {store.count_rows(conn, 'alerts')} alerts")
    for alert in alerts:
        print(f"  [{alert.severity:8}] {alert.rule:24} {alert.attack_id:10} {alert.src_ip:16} "
              f"{alert.attempts:3} attempts, {len(alert.users)} usernames")
    print(f"Report written to {args.output}")
    conn.close()


if __name__ == "__main__":
    main()
