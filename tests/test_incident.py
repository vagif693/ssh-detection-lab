import pytest

from sshlab import store
from sshlab.incident import build_report
from sshlab.parser import parse_file
from sshlab.rules import run_all_rules


@pytest.fixture
def conn(tmp_path):
    connection = store.connect(tmp_path / "incident.db")
    events, _ = parse_file("data/sample_attack.log")
    store.save_events(connection, events)
    store.save_alerts(connection, run_all_rules(store.load_events(connection)))
    return connection


def test_break_in_is_reported_as_compromise(conn):
    report = build_report(conn, "203.0.113.50")
    assert "Account compromised" in report
    assert "T1078" in report
    assert "**SUCCESSFUL LOGIN**" in report
    assert "reset the password" in report
    assert "`admin`" in report


def test_spraying_report(conn):
    report = build_report(conn, "198.51.100.23")
    assert "Password spraying" in report
    assert "T1110.003" in report
    assert "reset the password" not in report


def test_ip_without_alerts(conn):
    report = build_report(conn, "192.0.2.10")
    assert "No alerts" in report
    assert "No action needed" in report


def test_invalid_ip_is_rejected(conn):
    with pytest.raises(ValueError):
        build_report(conn, "10.0.0.1' OR '1'='1")


def test_long_timeline_is_shortened(tmp_path):
    connection = store.connect(tmp_path / "big.db")
    events, _ = parse_file("data/OpenSSH_2k.log")
    store.save_events(connection, events)
    store.save_alerts(connection, run_all_rules(store.load_events(connection)))
    report = build_report(connection, "183.62.140.253")
    assert "events omitted" in report
    assert "CRITICAL" in report
