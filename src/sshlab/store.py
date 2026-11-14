"""Keep events and alerts in SQLite so history survives between runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from sshlab.parser import Event
from sshlab.rules import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    line_hash   TEXT NOT NULL UNIQUE,
    timestamp   TEXT NOT NULL,
    host        TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    event_type  TEXT NOT NULL,
    user        TEXT,
    src_ip      TEXT,
    port        INTEGER,
    count       INTEGER NOT NULL DEFAULT 1,
    raw_line    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events (src_ip, timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    rule            TEXT NOT NULL,
    attack_id       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    src_ip          TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    attempts        INTEGER NOT NULL,
    peak_in_window  INTEGER NOT NULL,
    users           TEXT NOT NULL,
    evidence        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE (rule, src_ip, first_seen)
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (or create) the database and make sure the tables exist."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def line_hash(raw_line: str) -> str:
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def save_events(conn: sqlite3.Connection, events: list[Event]) -> int:
    """Store events, skipping ones already stored. Returns how many were new."""
    rows = [
        (line_hash(e.raw_line), e.timestamp.isoformat(), e.host, e.pid, e.event_type,
         e.user, e.src_ip, e.port, e.count, e.raw_line)
        for e in events
    ]
    before = conn.total_changes
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO events (line_hash, timestamp, host, pid, event_type, "
            "user, src_ip, port, count, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return conn.total_changes - before


def load_events(conn: sqlite3.Connection, src_ip: str | None = None) -> list[Event]:
    """Read events back in time order, optionally for one IP only."""
    query = ("SELECT timestamp, host, pid, event_type, user, src_ip, port, raw_line, count "
             "FROM events")
    params: tuple = ()
    if src_ip is not None:
        query += " WHERE src_ip = ?"
        params = (src_ip,)
    query += " ORDER BY timestamp, id"
    return [
        Event(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            host=row["host"],
            pid=row["pid"],
            event_type=row["event_type"],
            user=row["user"],
            src_ip=row["src_ip"],
            port=row["port"],
            raw_line=row["raw_line"],
            count=row["count"],
        )
        for row in conn.execute(query, params)
    ]


def save_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> None:
    """Insert new alerts; update ones we already have (the attack may have continued)."""
    now = datetime.now().isoformat(timespec="seconds")
    rows = [
        (a.rule, a.attack_id, a.severity, a.src_ip, a.first_seen.isoformat(),
         a.last_seen.isoformat(), a.attempts, a.peak_in_window,
         json.dumps(list(a.users)), json.dumps(list(a.evidence)), now)
        for a in alerts
    ]
    with conn:
        conn.executemany(
            "INSERT INTO alerts (rule, attack_id, severity, src_ip, first_seen, last_seen, "
            "attempts, peak_in_window, users, evidence, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (rule, src_ip, first_seen) DO UPDATE SET "
            "severity = excluded.severity, last_seen = excluded.last_seen, "
            "attempts = excluded.attempts, peak_in_window = excluded.peak_in_window, "
            "users = excluded.users, evidence = excluded.evidence",
            rows,
        )


def count_rows(conn: sqlite3.Connection, table: str) -> int:
    if table not in ("events", "alerts"):
        raise ValueError(f"unknown table: {table}")
    # nosec B608: the table name is checked against an allow-list above.
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _alert_row_to_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["users"] = json.loads(data["users"])
    data["evidence"] = json.loads(data["evidence"])
    return data


def list_alerts(conn: sqlite3.Connection, severity: str | None = None, limit: int = 50) -> list[dict]:
    """Alerts, most dangerous first, optionally only one severity."""
    query = "SELECT * FROM alerts"
    params: list = []
    if severity is not None:
        query += " WHERE severity = ?"
        params.append(severity)
    query += " ORDER BY peak_in_window DESC, id LIMIT ?"
    params.append(limit)
    return [_alert_row_to_dict(row) for row in conn.execute(query, params)]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _alert_row_to_dict(row) if row else None
