import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from minisiem.api import create_app

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from replay import load_samples  # noqa: E402

KEY = "test-key"
H = {"Authorization": f"Bearer {KEY}"}


@pytest.fixture
def client():
    return TestClient(create_app(KEY, ":memory:"))


def test_requires_api_key(client):
    for method, path in [("get", "/api/stats"), ("get", "/api/events"), ("get", "/api/alerts"),
                         ("post", "/api/ingest")]:
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/").status_code == 200  # static dashboard page itself holds no data


def test_create_app_refuses_empty_key():
    with pytest.raises(ValueError):
        create_app("", ":memory:")


def test_replayed_samples_raise_every_rule(client):
    res = client.post("/api/ingest", headers=H, json={"host": "ari", "records": load_samples()}).json()
    assert res["accepted"] == 74 and res["skipped"] == 1   # the "3 incorrect password attempts" summary line
    got = {a["rule"] for a in client.get("/api/alerts", headers=H, params={"limit": 1000}).json()}
    assert got == {"brute_force", "password_spray", "success_after_failures", "invalid_user", "port_scan",
                   "suspicious_http", "http_error_flood", "sudo_failures"}

    stats = client.get("/api/stats", headers=H).json()
    assert stats["total_events"] == 74 and stats["critical_alerts"] == 1
    assert stats["events_by_source"] == {"auth": 29, "web": 30, "firewall": 15}
    assert stats["top_ips"][0]["ip"] == "203.0.113.99"
    assert sum(p["count"] for p in stats["timeline"]) == 74


def test_filters(client):
    client.post("/api/ingest", headers=H, json={"host": "ari", "records": load_samples()})
    get = lambda path, **p: client.get(f"/api/{path}", headers=H, params=p).json()
    assert {e["event_type"] for e in get("events", event_type="auth_success")} == {"auth_success"}
    assert {e["src_ip"] for e in get("events", ip="203.0.113.50")} == {"203.0.113.50"}
    assert {a["severity"] for a in get("alerts", severity="critical")} == {"critical"}
    assert get("events", since="2026-11-10T09:10:00Z") == []
    assert len(get("events", since="2026-11-10T09:08:00Z")) == 15   # only the firewall log is that late
    assert len(get("events", limit=5)) == 5


def test_custom_app_event_and_validation(client):
    ok = {"kind": "event", "event": {"timestamp": "2026-11-10T10:00:00+05:30", "event_type": "app_login_failed",
                                      "src_ip": "10.1.1.1", "severity": "low"}}
    assert client.post("/api/ingest", headers=H, json={"records": [ok]}).json()["accepted"] == 1
    e = client.get("/api/events", headers=H).json()[0]
    assert e["timestamp"] == "2026-11-10T04:30:00.000000+00:00" and e["source"] == "app"
    bad = {"kind": "event", "event": {"timestamp": "2026-11-10T10:00:00Z", "event_type": "x", "severity": "huge"}}
    assert client.post("/api/ingest", headers=H, json={"records": [bad]}).status_code == 422
    assert client.post("/api/ingest", headers=H, json={"records": [{"kind": "shell", "line": "x"}]}).status_code == 422


def test_journal_records_route_to_parsers(client):
    records = [
        {"kind": "journal", "entry": {"__REALTIME_TIMESTAMP": "1762765200000000", "_HOSTNAME": "ari",
                                       "SYSLOG_IDENTIFIER": "sshd-session",
                                       "MESSAGE": "Failed password for root from 203.0.113.50 port 1 ssh2"}},
        {"kind": "journal", "entry": {"__REALTIME_TIMESTAMP": "1762765201000000", "_HOSTNAME": "ari",
                                       "_TRANSPORT": "kernel", "SYSLOG_IDENTIFIER": "kernel",
                                       "MESSAGE": "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.2 "
                                                  "PROTO=TCP SPT=5 DPT=22 SYN URGP=0"}},
        {"kind": "journal", "entry": {"__REALTIME_TIMESTAMP": "1762765202000000", "_TRANSPORT": "kernel",
                                       "MESSAGE": "usb 1-1: new device"}},
    ]
    assert client.post("/api/ingest", headers=H, json={"host": "ari", "records": records}).json() == \
        {"accepted": 2, "skipped": 1, "alerts": 1}
    evs = client.get("/api/events", headers=H).json()
    assert {e["event_type"] for e in evs} == {"auth_failure", "firewall_block"}
    assert all(e["host"] == "ari" for e in evs)
