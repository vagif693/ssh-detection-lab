"""Read-only HTTP API for alerts and IP timelines, protected by an API key."""

from __future__ import annotations

import ipaddress
import os
import secrets
from contextlib import closing
from datetime import datetime
from enum import Enum

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from sshlab import store

app = FastAPI(title="SSH Detection Lab", version="0.1.0")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class Severity(str, Enum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertOut(BaseModel):
    id: int
    rule: str
    attack_id: str
    severity: Severity
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int
    peak_in_window: int
    users: list[str]
    evidence: list[str]


class EventOut(BaseModel):
    timestamp: datetime
    event_type: str
    user: str | None
    port: int | None
    count: int
    raw_line: str


def db_path() -> str:
    return os.environ.get("SSHLAB_DB", "sshlab.db")


def require_api_key(provided: str | None = Security(api_key_header)) -> None:
    expected = os.environ.get("SSHLAB_API_KEY")
    if not expected:
        # Fail closed: without a configured key, nothing protected is served.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key not configured")
    if provided is None or not secrets.compare_digest(provided, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(require_api_key)])
def list_alerts(
    severity: Severity | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[dict]:
    with closing(store.connect(db_path())) as conn:
        return store.list_alerts(conn, severity.value if severity else None, limit)


@app.get("/alerts/{alert_id}", response_model=AlertOut, dependencies=[Depends(require_api_key)])
def get_alert(alert_id: int) -> dict:
    with closing(store.connect(db_path())) as conn:
        alert = store.get_alert(conn, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@app.get("/ips/{ip}/timeline", response_model=list[EventOut],
         dependencies=[Depends(require_api_key)])
def ip_timeline(ip: str) -> list:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Not a valid IP address")
    with closing(store.connect(db_path())) as conn:
        return store.load_events(conn, src_ip=ip)
