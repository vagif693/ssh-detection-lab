from datetime import datetime, timedelta

from sshlab import store
from sshlab.parser import Event
from sshlab.rules import Alert

START = datetime(2024, 12, 10, 6, 0, 0)


def event(ip: str, minute: int, event_type: str = "failed_password") -> Event:
    return Event(
        timestamp=START + timedelta(minutes=minute),
        host="test",
        pid=100 + minute,
        event_type=event_type,
        user="root",
        src_ip=ip,
        port=22,
        raw_line=f"{event_type} from {ip} at minute {minute}",
    )


def alert(attempts: int) -> Alert:
    return Alert(
        rule="ssh_brute_force", attack_id="T1110.001", severity="MEDIUM",
        src_ip="10.0.0.1", first_seen=START, last_seen=START + timedelta(minutes=attempts),
        attempts=attempts, peak_in_window=attempts, users=("root",), evidence=("line",),
    )


def test_events_round_trip(tmp_path):
    conn = store.connect(tmp_path / "lab.db")
    events = [event("10.0.0.1", m) for m in range(3)]
    store.save_events(conn, events)
    assert store.load_events(conn) == events


def test_ingesting_the_same_events_twice_adds_nothing(tmp_path):
    conn = store.connect(tmp_path / "lab.db")
    events = [event("10.0.0.1", m) for m in range(3)]
    assert store.save_events(conn, events) == 3
    assert store.save_events(conn, events) == 0
    assert store.count_rows(conn, "events") == 3


def test_load_events_for_one_ip(tmp_path):
    conn = store.connect(tmp_path / "lab.db")
    store.save_events(conn, [event("10.0.0.1", 0), event("10.0.0.2", 1)])
    loaded = store.load_events(conn, src_ip="10.0.0.2")
    assert [e.src_ip for e in loaded] == ["10.0.0.2"]


def test_sql_injection_in_ip_filter_returns_nothing(tmp_path):
    conn = store.connect(tmp_path / "lab.db")
    store.save_events(conn, [event("10.0.0.1", 0)])
    # With string-built SQL this would return every row. Placeholders keep it a plain value.
    assert store.load_events(conn, src_ip="x' OR '1'='1") == []


def test_alert_is_updated_not_duplicated(tmp_path):
    conn = store.connect(tmp_path / "lab.db")
    store.save_alerts(conn, [alert(5)])
    store.save_alerts(conn, [alert(9)])
    assert store.count_rows(conn, "alerts") == 1
    row = conn.execute("SELECT attempts FROM alerts").fetchone()
    assert row["attempts"] == 9


def test_data_survives_reopening_the_database(tmp_path):
    path = tmp_path / "lab.db"
    conn = store.connect(path)
    store.save_events(conn, [event("10.0.0.1", 0)])
    conn.close()
    assert store.count_rows(store.connect(path), "events") == 1
