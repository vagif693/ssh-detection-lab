"""Write a Markdown incident report for one source IP."""

from __future__ import annotations

import argparse
import ipaddress
import sqlite3
from datetime import datetime
from pathlib import Path

from sshlab import store
from sshlab.parser import Event

FENCE = "`" * 3
TIMELINE_LIMIT = 40
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def label_for(event: Event) -> str:
    if event.event_type == "accepted":
        return "**SUCCESSFUL LOGIN**"
    label = event.event_type.replace("_", " ").capitalize()
    return f"{label} (x{event.count})" if event.count > 1 else label


def verdict_for(alerts: list[dict]) -> str:
    rules = {a["rule"] for a in alerts}
    if "ssh_compromised_account" in rules:
        return "Account compromised: failed guesses were followed by a successful login."
    if "ssh_password_spraying" in rules:
        return "Password spraying: many usernames tried, no successful login."
    if "ssh_brute_force" in rules:
        return "Brute-force attempt: repeated password guesses, no successful login."
    return "No alerts: activity from this IP did not match any detection rule."


def response_steps(alerts: list[dict], events: list[Event]) -> list[str]:
    rules = {a["rule"] for a in alerts}
    if not rules:
        return ["No action needed. Keep monitoring."]
    steps = ["Block the source IP at the firewall (or with fail2ban) and watch for the same pattern from new IPs."]
    if "ssh_compromised_account" in rules:
        users = sorted({e.user for e in events if e.event_type == "accepted" and e.user})
        who = ", ".join(f"`{u}`" for u in users) or "the affected account"
        steps += [
            f"Treat {who} as compromised: reset the password and end all active sessions.",
            "Review what happened after the login: shell history, sudo use, files changed, outbound connections.",
            "Check for persistence: new users, `~/.ssh/authorized_keys`, cron jobs, systemd services.",
            "Rotate any secrets stored on or reachable from this host.",
        ]
    steps += [
        "Disable SSH password authentication and require keys, so guessing cannot succeed.",
        "Confirm no other IP logged in successfully during the same period.",
    ]
    return steps


def build_report(conn: sqlite3.Connection, ip: str) -> str:
    """Return a Markdown incident report for one IP."""
    ipaddress.ip_address(ip)  # raises ValueError for anything that is not an IP
    events = store.load_events(conn, src_ip=ip)
    alerts = [a for a in store.list_alerts(conn, limit=500) if a["src_ip"] == ip]
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))

    lines = [f"# Incident report: {ip}", ""]
    lines.append(f"Generated {datetime.now().isoformat(timespec='seconds')} by ssh-detection-lab.")
    lines += ["", "## Summary", ""]
    lines.append(f"**Verdict:** {verdict_for(alerts)}")
    lines.append("")
    if events:
        failed = sum(e.count for e in events if e.event_type == "failed_password")
        logins = [e for e in events if e.event_type == "accepted"]
        users = sorted({e.user for e in events if e.user})
        first, last = events[0].timestamp, events[-1].timestamp
        lines += [
            "| | |",
            "| --- | --- |",
            f"| Highest severity | {alerts[0]['severity'] if alerts else 'none'} |",
            f"| First seen | {first} |",
            f"| Last seen | {last} |",
            f"| Duration | {last - first} |",
            f"| Failed password attempts | {failed} |",
            f"| Successful logins | {len(logins)} |",
            f"| Usernames tried | {len(users)} |",
        ]
    else:
        lines.append("No events from this IP are stored.")

    lines += ["", "## Alerts", ""]
    if alerts:
        lines += ["| Severity | Rule | ATT&CK | Attempts | First seen | Last seen |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for a in alerts:
            first_seen = a["first_seen"].replace("T", " ")
            last_seen = a["last_seen"].replace("T", " ")
            lines.append(f"| {a['severity']} | {a['rule']} | {a['attack_id']} | {a['attempts']} "
                         f"| {first_seen} | {last_seen} |")
    else:
        lines.append("None.")

    lines += ["", "## Timeline", ""]
    shown = events
    if len(events) > TIMELINE_LIMIT:
        half = TIMELINE_LIMIT // 2
        shown = events[:half] + [None] + events[-half:]
    if events:
        lines += ["| Time | Event | User | Port |", "| --- | --- | --- | --- |"]
        for e in shown:
            if e is None:
                lines.append(f"| ... | {len(events) - TIMELINE_LIMIT} events omitted | | |")
                continue
            lines.append(f"| {e.timestamp} | {label_for(e)} | `{e.user}` | {e.port or ''} |")

    lines += ["", "## Recommended response", ""]
    lines += [f"{i}. {step}" for i, step in enumerate(response_steps(alerts, events), 1)]

    # Evidence lines from every alert, without duplicates, in the order they happened.
    position = {e.raw_line: i for i, e in enumerate(events)}
    evidence = sorted(set(line for a in alerts for line in a["evidence"]),
                      key=lambda line: position.get(line, -1))
    if evidence:
        lines += ["", "## Evidence", "", "Original log lines that triggered the alerts:", "", FENCE]
        lines += evidence
        lines.append(FENCE)
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Write an incident report for one IP.")
    parser.add_argument("ip", help="source IP to investigate")
    parser.add_argument("--db", default="sshlab.db", help="SQLite database file (default sshlab.db)")
    parser.add_argument("--output", help="write the report to this file instead of the screen")
    args = parser.parse_args()

    try:
        conn = store.connect(args.db)
        report = build_report(conn, args.ip)
    except ValueError:
        parser.error(f"not a valid IP address: {args.ip}")
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
