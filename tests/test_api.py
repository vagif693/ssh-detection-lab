from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sshlab import store
from sshlab.api import app
from sshlab.parser import Event
from sshlab.rules import detect_brute_force

KEY = "test-key-123"
START = datetime(2024, 12, 10, 6, 0, 0)


def failure(ip: str, minute: int) -> Event:
    return Event(START + timedelta(minutes=minute), "test", 100 + minute,
                 "failed_password", "root", ip, 22, f"fail {ip} {minute}")


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    conn = store.connect(db)
    events = [failure("10.0.0.1", m) for m in range(6)]       # MEDIUM attacker
    events += [failure("10.0.0.2", 0) for _ in range(1)]      # below threshold
    events += [Event(START + timedelta(seconds=s), "test", 500 + s, "failed_password",
                     "admin", "10.0.0.9", 22, f"fast {s}") for s in range(25)]  # HIGH
    store.save_events(conn, events)
    store.save_alerts(conn, detect_brute_force(store.load_events(conn)))
    conn.close()
    monkeypatch.setenv("SSHLAB_DB", str(db))
    monkeypatch.setenv("SSHLAB_API_KEY", KEY)
    return TestClient(app)


AUTH = {"X-API-Key": KEY}


def test_health_needs_no_key(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_key_is_rejected(client):
    assert client.get("/alerts").status_code == 401


def test_wrong_key_is_rejected(client):
    assert client.get("/alerts", headers={"X-API-Key": "guess"}).status_code == 401


def test_server_without_configured_key_refuses(client, monkeypatch):
    monkeypatch.delenv("SSHLAB_API_KEY")
    assert client.get("/alerts", headers=AUTH).status_code == 503


def test_alerts_listed_most_dangerous_first(client):
    response = client.get("/alerts", headers=AUTH)
    assert response.status_code == 200
    assert [a["src_ip"] for a in response.json()] == ["10.0.0.9", "10.0.0.1"]


def test_filter_by_severity(client):
    response = client.get("/alerts", params={"severity": "HIGH"}, headers=AUTH)
    assert [a["src_ip"] for a in response.json()] == ["10.0.0.9"]


def test_unknown_severity_is_rejected(client):
    assert client.get("/alerts", params={"severity": "PANIC"}, headers=AUTH).status_code == 422


def test_limit_has_a_maximum(client):
    assert client.get("/alerts", params={"limit": 100000}, headers=AUTH).status_code == 422


def test_get_one_alert_with_evidence(client):
    first = client.get("/alerts", headers=AUTH).json()[0]
    response = client.get(f"/alerts/{first['id']}", headers=AUTH)
    assert response.status_code == 200
    assert response.json()["evidence"]


def test_missing_alert_is_404(client):
    assert client.get("/alerts/9999", headers=AUTH).status_code == 404


def test_ip_timeline_in_time_order(client):
    response = client.get("/ips/10.0.0.1/timeline", headers=AUTH)
    assert response.status_code == 200
    times = [e["timestamp"] for e in response.json()]
    assert len(times) == 6 and times == sorted(times)


@pytest.mark.parametrize("bad_ip", ["not-an-ip", "999.1.1.1", "10.0.0.1' OR '1'='1"])
def test_invalid_ip_is_rejected(client, bad_ip):
    assert client.get(f"/ips/{bad_ip}/timeline", headers=AUTH).status_code == 422
