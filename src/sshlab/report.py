"""Write alerts as a JSON report."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from sshlab.rules import Alert


def alert_to_dict(alert: Alert) -> dict:
    data = asdict(alert)
    for key, value in data.items():
        if isinstance(value, datetime):
            data[key] = value.isoformat()
        elif isinstance(value, tuple):
            data[key] = list(value)
    return data


def write_report(alerts: list[Alert], path: str | Path, source: str, skipped: int) -> None:
    report = {
        "source": source,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "skipped_lines": skipped,
        "alert_count": len(alerts),
        "alerts": [alert_to_dict(a) for a in alerts],
    }
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")
