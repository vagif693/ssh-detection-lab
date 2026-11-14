"""Detection rules: decide which events are suspicious."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from sshlab.parser import Event

WINDOW = timedelta(minutes=10)
THRESHOLD = 5

# Highest level first: the first limit an attacker reaches sets the severity.
SEVERITY_LEVELS = [(100, "CRITICAL"), (20, "HIGH"), (5, "MEDIUM")]


@dataclass(frozen=True)
class Alert:
    rule: str
    attack_id: str
    severity: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int
    peak_in_window: int
    users: tuple[str, ...]
    evidence: tuple[str, ...]


def severity_for(peak: int) -> str:
    for limit, level in SEVERITY_LEVELS:
        if peak >= limit:
            return level
    return "LOW"


def detect_brute_force(
    events: list[Event], window: timedelta = WINDOW, threshold: int = THRESHOLD
) -> list[Alert]:
    """Flag IPs with `threshold` or more failed passwords inside any `window`."""
    failures: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_password" and event.src_ip:
            failures[event.src_ip].append(event)

    alerts = []
    for ip, ip_events in failures.items():
        ip_events.sort(key=lambda e: e.timestamp)

        in_window: deque[Event] = deque()
        window_total = 0
        peak = 0
        for event in ip_events:
            in_window.append(event)
            window_total += event.count
            while event.timestamp - in_window[0].timestamp > window:
                window_total -= in_window.popleft().count
            peak = max(peak, window_total)

        if peak < threshold:
            continue

        users = sorted({e.user for e in ip_events if e.user})
        alerts.append(Alert(
            rule="ssh_brute_force",
            attack_id="T1110.001",
            severity=severity_for(peak),
            src_ip=ip,
            first_seen=ip_events[0].timestamp,
            last_seen=ip_events[-1].timestamp,
            attempts=sum(e.count for e in ip_events),
            peak_in_window=peak,
            users=tuple(users),
            evidence=tuple(e.raw_line for e in ip_events[:5]),
        ))

    alerts.sort(key=lambda a: a.peak_in_window, reverse=True)
    return alerts
