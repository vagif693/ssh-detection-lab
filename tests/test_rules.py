from datetime import datetime, timedelta

from sshlab.parser import Event
from sshlab.rules import (
    detect_brute_force,
    detect_compromised_accounts,
    detect_password_spraying,
    run_all_rules,
    severity_for,
)

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


# --- Compromised account: failures followed by a success from the same IP ---


def success(ip: str, minute: float, user: str = "root") -> Event:
    return Event(START + timedelta(minutes=minute), "test", 2, "accepted", user, ip, 22,
                 f"success for {user} from {ip} at minute {minute}")


def test_success_after_many_failures_is_a_compromise():
    events = [failure("10.0.0.1", m, user="admin") for m in range(5)]
    events.append(success("10.0.0.1", 6, user="admin"))
    alerts = detect_compromised_accounts(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].attack_id == "T1078"
    assert alerts[0].users == ("admin",)
    assert alerts[0].evidence[-1].startswith("success")


def test_two_typos_then_success_is_not_a_compromise():
    events = [failure("10.0.0.1", 0), failure("10.0.0.1", 1), success("10.0.0.1", 2)]
    assert detect_compromised_accounts(events) == []


def test_success_from_a_different_ip_is_not_linked():
    events = [failure("10.0.0.1", m) for m in range(5)]
    events.append(success("10.0.0.2", 6))
    assert detect_compromised_accounts(events) == []


def test_success_long_after_failures_is_not_linked():
    events = [failure("10.0.0.1", m) for m in range(5)]
    events.append(success("10.0.0.1", 180))  # three hours later
    assert detect_compromised_accounts(events) == []


# --- Password spraying: many usernames, few guesses each ---

def test_many_usernames_one_guess_each_is_spraying():
    events = [failure("10.0.0.7", m * 3, user=f"user{m}") for m in range(12)]
    alerts = detect_password_spraying(events)
    assert len(alerts) == 1
    assert alerts[0].attack_id == "T1110.003"
    assert alerts[0].peak_in_window == 12


def test_slow_spraying_evades_the_brute_force_rule():
    # One guess every 3 minutes never reaches 5 in 10 minutes.
    events = [failure("10.0.0.7", m * 3, user=f"user{m}") for m in range(12)]
    assert detect_brute_force(events) == []
    assert len(detect_password_spraying(events)) == 1


def test_one_username_many_guesses_is_not_spraying():
    events = [failure("10.0.0.1", m, user="root") for m in range(30)]
    assert detect_password_spraying(events) == []


def test_usernames_spread_over_a_day_are_not_spraying():
    events = [failure("10.0.0.7", m * 120, user=f"user{m}") for m in range(12)]
    assert detect_password_spraying(events) == []


def test_run_all_rules_puts_critical_first():
    events = [failure("10.0.0.1", m * 0.5, user="admin") for m in range(8)]
    events.append(success("10.0.0.1", 5, user="admin"))
    severities = [a.severity for a in run_all_rules(events)]
    assert severities == ["CRITICAL", "MEDIUM"]
