"""Alert raised by the detection engine."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Alert:
    timestamp: datetime      # time of the event that triggered the alert (UTC)
    rule: str                # rule id, e.g. "brute_force"
    title: str               # attack / event type shown to analysts
    severity: str            # "low" | "medium" | "high" | "critical"
    description: str
    mitre: str               # MITRE ATT&CK technique id
    src_ip: str | None = None
    host: str | None = None
    user: str | None = None
    evidence: list[str] = field(default_factory=list)   # raw log lines that led to the alert

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d
