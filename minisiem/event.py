"""Normalized security event shared by every parser, the detection engine and the API."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Event:
    timestamp: datetime          # timezone-aware, UTC
    source: str                  # "auth" | "web" | "firewall" | "windows" | "app"
    event_type: str              # e.g. "auth_failure", "http_request", "firewall_block"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    action: str | None = None    # e.g. HTTP method, "block", "login"
    status: str | None = None    # e.g. "200", "failure", "success"
    severity: str = "info"
    host: str | None = None      # machine that produced the log
    raw: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        d = dict(d)
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        return cls(**d)
