"""FastAPI backend: ingest raw logs from agents, run detection, serve events, alerts and stats."""
from __future__ import annotations

import hmac
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from minisiem.db import Database
from minisiem.detection import Detector, load_config
from minisiem.event import SEVERITIES, Event
from minisiem.parsers import auth, firewall, web

MAX_RECORDS = 5000
MAX_LINE = 16_384


class Record(BaseModel):
    kind: Literal["auth", "web", "firewall", "journal", "event"]
    line: str | None = Field(default=None, max_length=MAX_LINE)
    entry: dict[str, Any] | None = None   # one `journalctl -o json` object
    event: dict[str, Any] | None = None   # custom application event (Event fields)


class Batch(BaseModel):
    host: str | None = Field(default=None, max_length=255)
    records: list[Record] = Field(max_length=MAX_RECORDS)


class AppEvent(BaseModel):
    """Custom application event; validated before it becomes an Event."""
    timestamp: datetime
    event_type: str = Field(max_length=64)
    source: str = Field(default="app", max_length=32)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    user: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=64)
    severity: Literal[SEVERITIES] = "info"
    host: str | None = Field(default=None, max_length=255)
    raw: str = Field(default="", max_length=MAX_LINE)
    meta: dict[str, Any] = Field(default_factory=dict)


def parse_record(r: Record, host: str | None) -> Event | None:
    if r.kind == "event":
        return Event(**AppEvent(**(r.event or {})).model_dump()) if r.event else None
    if r.kind == "journal":
        e = r.entry or {}
        if e.get("_TRANSPORT") == "kernel" or e.get("SYSLOG_IDENTIFIER") == "kernel":
            try:
                ts = datetime.fromtimestamp(int(e["__REALTIME_TIMESTAMP"]) / 1_000_000, tz=timezone.utc)
            except (KeyError, ValueError, TypeError):
                return None
            msg = e.get("MESSAGE")
            return firewall.parse_line(msg, host=e.get("_HOSTNAME") or host, default_time=ts) \
                if isinstance(msg, str) else None
        ev = auth.parse_journal(e)
    elif r.line is None:
        return None
    elif r.kind == "auth":
        ev = auth.parse_line(r.line)
    elif r.kind == "web":
        ev = web.parse_line(r.line, host=host)
    else:
        ev = firewall.parse_line(r.line, host=host)
    if ev is not None and ev.host is None:
        ev.host = host
    return ev


def create_app(api_key: str, db_path: str = "minisiem.db", rules_path: str | None = None) -> FastAPI:
    if not api_key:
        raise ValueError("an API key is required")
    db = Database(db_path)
    detector = Detector(load_config(rules_path))
    detect_lock = threading.Lock()  # detector windows are not thread-safe
    app = FastAPI(title="Mini SIEM")
    app.state.db = db

    def require_key(authorization: str = Header(default="")) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(token.encode(), api_key.encode()):
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    auth_dep = [Depends(require_key)]

    @app.post("/api/ingest", dependencies=auth_dep)
    def ingest(batch: Batch) -> dict:
        events, skipped = [], 0
        for r in batch.records:
            try:
                ev = parse_record(r, batch.host)
            except ValueError as exc:  # invalid custom event
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if ev is None:
                skipped += 1
                continue
            ev.timestamp = ev.timestamp.astimezone(timezone.utc) if ev.timestamp.tzinfo \
                else ev.timestamp.replace(tzinfo=timezone.utc)
            events.append(ev)
        events.sort(key=lambda e: e.timestamp)
        with detect_lock:
            alerts = [a for ev in events for a in detector.process(ev)]
        db.insert_events(events)
        db.insert_alerts(alerts)
        return {"accepted": len(events), "skipped": skipped, "alerts": len(alerts)}

    @app.get("/api/events", dependencies=auth_dep)
    def events(severity: str | None = None, event_type: str | None = None, source: str | None = None,
               ip: str | None = None, host: str | None = None, since: datetime | None = None,
               until: datetime | None = None, limit: int = Query(default=100, ge=1, le=1000)) -> list[dict]:
        return db.events(limit, severity=severity, event_type=event_type, source=source, ip=ip, host=host,
                         since=since, until=until)

    @app.get("/api/alerts", dependencies=auth_dep)
    def alerts(severity: str | None = None, rule: str | None = None, ip: str | None = None,
               host: str | None = None, since: datetime | None = None, until: datetime | None = None,
               limit: int = Query(default=100, ge=1, le=1000)) -> list[dict]:
        return db.alerts(limit, severity=severity, rule=rule, ip=ip, host=host, since=since, until=until)

    @app.get("/api/stats", dependencies=auth_dep)
    def stats() -> dict:
        return db.stats()

    app.mount("/", StaticFiles(directory=Path(__file__).parent / "dashboard", html=True), name="dashboard")
    return app
