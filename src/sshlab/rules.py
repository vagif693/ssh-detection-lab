"""Detection rules: decide which events are suspicious."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
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


SUCCESS_WINDOW = timedelta(hours=1)
MIN_FAILURES_BEFORE_SUCCESS = 3


def detect_compromised_accounts(
    events: list[Event],
    window: timedelta = SUCCESS_WINDOW,
    min_failures: int = MIN_FAILURES_BEFORE_SUCCESS,
) -> list[Alert]:
    """Flag a successful login that follows several failures from the same IP."""
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type in ("failed_password", "accepted") and event.src_ip:
            by_ip[event.src_ip].append(event)

    alerts = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        for i, event in enumerate(ip_events):
            if event.event_type != "accepted":
                continue
            failures = [
                e for e in ip_events[:i]
                if e.event_type == "failed_password"
                and event.timestamp - e.timestamp <= window
            ]
            attempts = sum(e.count for e in failures)
            if attempts < min_failures:
                continue
            alerts.append(Alert(
                rule="ssh_compromised_account",
                attack_id="T1078",
                severity="CRITICAL",
                src_ip=ip,
                first_seen=failures[0].timestamp,
                last_seen=event.timestamp,
                attempts=attempts,
                peak_in_window=attempts,
                users=(event.user,) if event.user else (),
                evidence=tuple(e.raw_line for e in failures[-4:]) + (event.raw_line,),
            ))
    return alerts


SPRAY_WINDOW = timedelta(hours=1)
SPRAY_MIN_USERS = 10
SPRAY_MAX_ATTEMPTS_PER_USER = 3


def detect_password_spraying(
    events: list[Event],
    window: timedelta = SPRAY_WINDOW,
    min_users: int = SPRAY_MIN_USERS,
    max_per_user: float = SPRAY_MAX_ATTEMPTS_PER_USER,
) -> list[Alert]:
    """Flag an IP that tries many different usernames with only a few guesses each."""
    failures: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_password" and event.src_ip and event.user:
            failures[event.src_ip].append(event)

    alerts = []
    for ip, ip_events in failures.items():
        ip_events.sort(key=lambda e: e.timestamp)

        in_window: deque[Event] = deque()
        per_user: Counter[str] = Counter()
        best_users = 0
        for event in ip_events:
            in_window.append(event)
            per_user[event.user] += event.count
            while event.timestamp - in_window[0].timestamp > window:
                old = in_window.popleft()
                per_user[old.user] -= old.count
                if per_user[old.user] <= 0:
                    del per_user[old.user]
            attempts = sum(per_user.values())
            if len(per_user) >= min_users and attempts / len(per_user) <= max_per_user:
                best_users = max(best_users, len(per_user))

        if best_users == 0:
            continue
        users = sorted({e.user for e in ip_events})
        alerts.append(Alert(
            rule="ssh_password_spraying",
            attack_id="T1110.003",
            severity="HIGH",
            src_ip=ip,
            first_seen=ip_events[0].timestamp,
            last_seen=ip_events[-1].timestamp,
            attempts=sum(e.count for e in ip_events),
            peak_in_window=best_users,
            users=tuple(users),
            evidence=tuple(e.raw_line for e in ip_events[:5]),
        ))
    return alerts


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run_all_rules(events: list[Event], window: timedelta = WINDOW,
                  threshold: int = THRESHOLD) -> list[Alert]:
    """Run every rule and return alerts, most severe first."""
    alerts = (
        detect_compromised_accounts(events)
        + detect_password_spraying(events)
        + detect_brute_force(events, window, threshold)
    )
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.peak_in_window))
    return alerts
