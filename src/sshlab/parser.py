"""Turn OpenSSH auth log lines into structured events."""

from __future__ import annotations

import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Syslog timestamps have no year ("Dec 10 06:55:46"), so we assume one.
DEFAULT_YEAR = 2024

HEADER = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)

MESSAGES = [
    ("failed_password", re.compile(
        r"^Failed password for (?:invalid user )?(?P<user>\S*) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("accepted", re.compile(
        r"^Accepted (?:password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")),
]


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    pid: int
    event_type: str
    user: str | None
    src_ip: str | None
    port: int | None
    raw_line: str


def parse_line(line: str, year: int = DEFAULT_YEAR) -> Event | None:
    """Return an Event for a line we understand, or None for anything else."""
    line = line.rstrip("\n")
    header = HEADER.match(line)
    if header is None:
        return None

    message = header["msg"]
    for event_type, pattern in MESSAGES:
        found = pattern.match(message)
        if found:
            timestamp = datetime.strptime(
                f"{year} {header['ts']}", "%Y %b %d %H:%M:%S"
            )
            port = found["port"]
            return Event(
                timestamp=timestamp,
                host=header["host"],
                pid=int(header["pid"]),
                event_type=event_type,
                user=found["user"] or None,
                src_ip=found["ip"],
                port=int(port) if port else None,
                raw_line=line,
            )
    return None


def parse_file(path: str | Path, year: int = DEFAULT_YEAR) -> tuple[list[Event], int]:
    """Parse a whole log file. Returns (events, number_of_skipped_lines)."""
    events: list[Event] = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as log:
        for line in log:
            event = parse_line(line, year)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return events, skipped


if __name__ == "__main__":
    events, skipped = parse_file(sys.argv[1])
    print(f"Parsed {len(events)} events, skipped {skipped} lines")
    for event_type, count in Counter(e.event_type for e in events).most_common():
        print(f"  {event_type}: {count}")
