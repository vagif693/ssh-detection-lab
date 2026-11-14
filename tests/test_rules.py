from datetime import datetime, timedelta

from sshlab.parser import Event
from sshlab.rules import detect_brute_force, severity_for

START = datetime(2024, 12, 10, 6, 0, 0)


def failure(ip: str, minute: float, user: str = "root", count: int = 1) -> Event:
    return Event(
        timestamp=START + timedelta(minutes=minute),
        host="test",
        pid=1,
        event_type="failed_password",
        user=user,
        src_ip=ip,
        port=22,
        raw_line=f"failure from {ip} at minute {minute}",
        count=count,
    )


def test_five_failures_in_ten_minutes_raise_an_alert():
    events = [failure("10.0.0.1", m) for m in range(5)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.1"
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].attack_id == "T1110.001"


def test_four_failures_stay_below_threshold():
    events = [failure("10.0.0.1", m) for m in range(4)]
    assert detect_brute_force(events) == []


def test_failures_spread_over_hours_are_not_an_attack():
    # 6 failures, 30 minutes apart: a forgetful user, not a brute force.
    events = [failure("10.0.0.1", m * 30) for m in range(6)]
    assert detect_brute_force(events) == []


def test_repeated_message_counts_toward_threshold():
    events = [failure("10.0.0.1", 0, count=5)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].attempts == 5


def test_each_ip_is_judged_separately():
    events = [failure("10.0.0.1", m) for m in range(3)]
    events += [failure("10.0.0.2", m) for m in range(3)]
    assert detect_brute_force(events) == []


def test_successful_logins_are_not_counted_as_failures():
    events = [failure("10.0.0.1", m) for m in range(4)]
    success = Event(START, "test", 1, "accepted", "root", "10.0.0.1", 22, "ok")
    assert detect_brute_force(events + [success]) == []


def test_usernames_tried_are_collected():
    events = [failure("10.0.0.1", m, user=u) for m, u in enumerate(["root", "admin", "test", "root", "oracle"])]
    alerts = detect_brute_force(events)
    assert alerts[0].users == ("admin", "oracle", "root", "test")


def test_severity_levels():
    assert severity_for(5) == "MEDIUM"
    assert severity_for(20) == "HIGH"
    assert severity_for(100) == "CRITICAL"
