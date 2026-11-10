"""SQLite storage for events and alerts."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from minisiem.alerts import Alert
from minisiem.event import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, source TEXT, event_type TEXT, src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER, user TEXT, action TEXT, status TEXT, severity TEXT, host TEXT,
    raw TEXT, meta TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, rule TEXT, title TEXT, severity TEXT, description TEXT,
    mitre TEXT, src_ip TEXT, host TEXT, user TEXT, evidence TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
"""


def ts_key(t: datetime) -> str:
    """Fixed-width UTC string so SQL string comparison equals time comparison."""
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).isoformat(timespec="microseconds")


class Database:
    def __init__(self, path: str = "minisiem.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            if path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)

    def insert_events(self, events: list[Event]) -> None:
        rows = [(ts_key(e.timestamp), e.source, e.event_type, e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.user,
                 e.action, e.status, e.severity, e.host, e.raw, json.dumps(e.meta)) for e in events]
        with self.lock, self.conn:
            self.conn.executemany(
                "INSERT INTO events (ts, source, event_type, src_ip, dst_ip, src_port, dst_port, user, action,"
                " status, severity, host, raw, meta) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def insert_alerts(self, alerts: list[Alert]) -> None:
        rows = [(ts_key(a.timestamp), a.rule, a.title, a.severity, a.description, a.mitre, a.src_ip, a.host,
                 a.user, json.dumps(a.evidence)) for a in alerts]
        with self.lock, self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (ts, rule, title, severity, description, mitre, src_ip, host, user, evidence)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)", rows)

    def _select(self, table: str, filters: dict, limit: int, json_col: str) -> list[dict]:
        where, args = [], []
        for col in ("severity", "event_type", "source", "rule", "host"):
            if filters.get(col):
                where.append(f"{col} = ?")
                args.append(filters[col])
        if filters.get("ip"):
            where.append("(src_ip = ? OR dst_ip = ?)" if table == "events" else "src_ip = ?")
            args += [filters["ip"]] * (2 if table == "events" else 1)
        if filters.get("since"):
            where.append("ts >= ?")
            args.append(ts_key(filters["since"]))
        if filters.get("until"):
            where.append("ts <= ?")
            args.append(ts_key(filters["until"]))
        sql = f"SELECT * FROM {table}" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        with self.lock:
            rows = self.conn.execute(sql, args + [limit]).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["timestamp"] = d.pop("ts")
            d[json_col] = json.loads(d[json_col])
            out.append(d)
        return out

    def events(self, limit: int = 100, **filters) -> list[dict]:
        return self._select("events", filters, limit, "meta")

    def alerts(self, limit: int = 100, **filters) -> list[dict]:
        return self._select("alerts", filters, limit, "evidence")

    def stats(self) -> dict:
        q = lambda sql: self.conn.execute(sql).fetchall()
        with self.lock:
            total_events = q("SELECT COUNT(*) FROM events")[0][0]
            by_sev = {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
            top_ips = q("SELECT src_ip, COUNT(*) n FROM events WHERE src_ip IS NOT NULL"
                        " GROUP BY src_ip ORDER BY n DESC LIMIT 10")
            attack_types = q("SELECT title, COUNT(*) n FROM alerts GROUP BY title ORDER BY n DESC")
            by_source = q("SELECT source, COUNT(*) FROM events GROUP BY source")
            # per-minute buckets; the newest 60 minutes that have data, so replayed old logs still chart
            timeline = q("SELECT substr(ts, 1, 16) m, COUNT(*) FROM events GROUP BY m ORDER BY m DESC LIMIT 60")
            alert_timeline = q("SELECT substr(ts, 1, 16) m, COUNT(*) FROM alerts GROUP BY m ORDER BY m DESC LIMIT 60")
        return {
            "total_events": total_events,
            "total_alerts": sum(by_sev.values()),
            "alerts_by_severity": by_sev,
            "critical_alerts": by_sev.get("critical", 0),
            "high_alerts": by_sev.get("high", 0),
            "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
            "attack_types": [{"type": r[0], "count": r[1]} for r in attack_types],
            "events_by_source": {r[0]: r[1] for r in by_source},
            "timeline": [{"minute": r[0], "count": r[1]} for r in reversed(timeline)],
            "alert_timeline": [{"minute": r[0], "count": r[1]} for r in reversed(alert_timeline)],
        }
