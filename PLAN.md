# Mini SIEM: Build Plan

Lightweight SIEM: collect logs, normalize to one event schema, detect attacks with rules,
raise alerts, and show everything on a web dashboard.

## Platform

- Server and dashboard: cross-platform Python (Windows or Linux).
- Log sources: Linux first (journald / auth.log, ufw / iptables, nginx / apache access logs).
  Windows Security log (4624 / 4625) is a stretch collector via `wevtutil`.
- Agent (`minisiem/agent.py`): stdlib only, so it runs on any monitored host without pip.

## Stack

- FastAPI + uvicorn backend, SQLite (stdlib `sqlite3`, WAL mode).
- Dashboard: static HTML + Bootstrap + Chart.js, served by FastAPI.
- Rule thresholds in `rules.toml` (stdlib `tomllib`).
- Out of scope for now (future scope): PostgreSQL, ML anomaly detection, notifications, RBAC.

## Layout

```
minisiem/
  event.py               normalized Event
  parsers/auth.py        journald JSON, auth.log, sudo
  parsers/web.py         Apache / Nginx combined + common log format      [worker W1]
  parsers/firewall.py    UFW / iptables kernel LOG lines                  [worker W2]
  parsers/windows.py     Windows Security events (stretch)
  detection/engine.py    sliding windows keyed by IP / user
  detection/rules.py     rule implementations
  detection/http_signatures.py  SQLi / XSS / traversal / scanner UA       [worker W3, optional]
  alerts.py              alert creation + duplicate suppression
  db.py                  SQLite schema and queries
  api.py                 POST /api/ingest, GET /api/events, /api/alerts, /api/stats
  agent.py               tail files / journalctl, batch, ship to server
  dashboard/             index.html, app.js
tools/replay.py          replay samples/*.log into the server
tools/demo_web.py        small target web app that writes a combined-format access log
tools/e2e_check.py       assert expected alerts exist via the API
tests/
```

## Detection rules

| Rule | Logic | Severity | ATT&CK |
|---|---|---|---|
| Brute force | >= 5 failed logins, same IP, 60 s | HIGH | T1110.001 |
| Password spray | >= 5 distinct users failed, same IP, 5 min | HIGH | T1110.003 |
| Success after failures | success from an IP with >= 3 failures in 10 min | CRITICAL | T1078 |
| Invalid / root login attempt | invalid user or root login attempt | MEDIUM | T1078 |
| Port scan | >= 10 distinct destination ports, same IP, 60 s | HIGH | T1046 |
| Suspicious HTTP | SQLi / XSS / path traversal / scanner user agent | MEDIUM / HIGH | T1190 |
| HTTP error flood | >= 20 responses 401 / 403 / 404 per IP per minute | MEDIUM | T1595 |
| sudo failures | >= 3 sudo auth failures, 5 min | MEDIUM | T1548.003 |

## Work split

The main machine does the heavy lifting. The HiveMind worker `ari` (aider on a free OpenRouter
key) gets small, isolated, pure-function tasks with tests written in advance.

| Task | Owner | Gate |
|---|---|---|
| Scaffold, Event schema, stubs, worker tests | main | - |
| W1 `parsers/web.py` | worker | `python3 -m unittest tests.test_web_parser -v` |
| W2 `parsers/firewall.py` | worker | `python3 -m unittest tests.test_firewall_parser -v` |
| W3 `detection/http_signatures.py` (if W1/W2 go well) | worker | `python3 -m unittest tests.test_http_signatures -v` |
| Auth parser, DB, engine, rules, alerts, API, agent, dashboard, tools, CI | main | `pytest` |
| Review + merge worker branches (`hive_merge`) | main | full test suite |

Worker tests use stdlib `unittest` because the worker has no pytest installed.

## Cross-machine test (over Tailscale)

- Windows main machine: SIEM server on port 8000, plus the attacker.
- `ari` (Linux): monitored host running `agent.py` (journald + ufw logs) and `tools/demo_web.py`.
- Attacks from main machine to `ari`: nmap port scan, about 8 failed SSH logins,
  SQLi / traversal HTTP requests. Then `tools/e2e_check.py` asserts the alerts.
- Prerequisites on `ari`: `sudo usermod -aG adm,systemd-journal lakshya` and `sudo ufw logging on`.
- Single-machine fallback (and CI): `tools/replay.py` on `samples/` gives the same alerts.

## Order

1. Scaffold, stubs, worker tests. Create the public GitHub repo and push.
2. Dispatch W1 + W2 to the worker in parallel; build the core here meanwhile.
3. Review and merge worker branches; dispatch W3 if it makes sense.
4. Replay demo, then cross-machine E2E.
