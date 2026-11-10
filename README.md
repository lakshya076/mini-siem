# Mini SIEM

A lightweight Security Information and Event Management system for real-time threat detection
and monitoring. Agents collect system and application logs, the server normalizes them into one
event schema, runs rule-based detection, raises alerts and shows everything on a web dashboard.

Made with [Hive](https://github.com/lakshya076/HiveMind)

```
 monitored host(s)                              SIEM server (Windows or Linux)
 ┌──────────────────────┐   HTTP + API key   ┌──────────────────────────────────────────┐
 │ agent.py             │ ─────────────────► │ /api/ingest → parsers → detection engine │
 │  journald (sshd,sudo,│                    │                 │              │         │
 │  kernel/ufw)         │                    │              SQLite ◄──── alerts         │
 │  access.log, ufw.log │                    │                 │                        │
 └──────────────────────┘                    │ /api/events /api/alerts /api/stats       │
                                             │ dashboard (Bootstrap + Chart.js)         │
                                             └──────────────────────────────────────────┘
```

## Contents

1. [About the project](#about-the-project)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Install](#install)
5. [Run the server](#run-the-server)
6. [Open the dashboard](#open-the-dashboard)
7. [Try it on one machine (replay demo)](#try-it-on-one-machine-replay-demo)
8. [Monitor other machines](#monitor-other-machines)
9. [Lab attack simulation](#lab-attack-simulation)
10. [Detection rules](#detection-rules)
11. [API reference](#api-reference)
12. [Project layout](#project-layout)
13. [Tests](#tests)
14. [Troubleshooting](#troubleshooting)
15. [Security notes](#security-notes)

## About the project

**The problem.** Computers and networks produce a steady stream of security-relevant logs:
logins, web requests, firewall decisions, privilege changes. Reading them by hand is slow, so
attacks such as password guessing or port scanning are easy to miss while they happen. Commercial
SIEM platforms solve this, but they are complex, expensive and built for large enterprises.

**What Mini SIEM is.** A small, transparent SIEM for learning and for small or lab environments. It
implements the core SIEM pipeline end to end, in code short enough to read:

1. **Collect:** a lightweight agent on each monitored machine gathers authentication, web server,
   firewall and application logs and sends them to a central server.
2. **Normalize:** parsers turn each raw log line into one standard event format (time, source and
   destination IP, event type, user, action, status, severity, host).
3. **Store:** events and alerts are kept in a SQLite database, giving an audit trail of what
   happened, when, from where and how severe it was.
4. **Detect:** a rule engine watches the event stream over sliding time windows and recognizes
   brute-force logins, password spraying, logins that succeed after many failures, port scans,
   web attacks (SQL injection, XSS, path traversal), content discovery and repeated sudo failures.
   Each rule is mapped to a MITRE ATT&CK technique.
5. **Alert and visualize:** detections become alerts with severity, description and the raw log
   lines as evidence, shown on a web dashboard with statistics, charts and filters.

**What it is for.** Demonstrating security monitoring, log analysis and intrusion detection in
teaching, cybersecurity training, controlled lab experiments (attack a test machine and watch the
alerts appear), and basic central monitoring for small setups. It is not meant to replace an
enterprise SIEM; the goal is to show clearly how one works and to be easy to extend with new log
sources and detection rules.

**How it was built.** Python with FastAPI for the backend, SQLite for storage, and HTML, Bootstrap
and Chart.js for the dashboard. It was tested live between two machines: a Windows PC running the
server and the simulated attacks, and a Debian Linux host being monitored. Part of the code (the web
and firewall log parsers and the HTTP attack signatures) was written by a remote AI coding worker
orchestrated with [HiveMind](https://github.com/lakshya076/HiveMind), against tests written in advance.

## Features

- **Log collection:** a single-file agent (Python standard library only) follows journald (sshd,
  sudo, kernel firewall messages) and tails log files, surviving log rotation.
- **Parsing and normalization:** Linux auth logs (auth.log and journald), Apache/Nginx access logs,
  UFW/iptables firewall logs, and custom JSON application events, all mapped to one event schema
  (timestamp, source/destination IP and port, event type, user, action, status, severity, host, raw line).
- **Detection engine:** 8 sliding-window rules mapped to MITRE ATT&CK, with duplicate-alert suppression.
  Thresholds can be changed in a TOML file.
- **Alerts:** attack type, source, timestamp, severity, description, evidence (the raw log lines)
  and the rule that fired.
- **Dashboard:** total events and alerts, critical and high alert counts, event timeline, attack types,
  most active IPs, alert and event tables, and filters by severity, event type, IP and time period.

## Requirements

- Python 3.11 or newer on the server (3.12 / 3.13 tested).
- Python 3.8 or newer on monitored hosts (the agent uses only the standard library).
- Git, to clone the repository.
- For live tests between machines: network reachability between them (same LAN or
  [Tailscale](https://tailscale.com)).

Works on Windows and Linux. The log sources (journald, ufw, Nginx) are Linux; a Windows machine can
run the server and the attack tools.

## Install

```bash
git clone https://github.com/lakshya076/mini-siem.git
cd mini-siem
python -m venv .venv
```

Activate the virtual environment:

| Shell | Command |
|---|---|
| Linux / macOS (bash, zsh) | `source .venv/bin/activate` |
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows cmd | `.venv\Scripts\activate.bat` |

Then install the package with its development extras (pytest, httpx):

```bash
pip install -e ".[dev]"
```

`pip install -e .` is needed for the scripts in `tools/`, which import the `minisiem` package.

## Run the server

1. Choose an API key. Agents, tools and the dashboard all use it.

   ```bash
   # Linux / macOS
   export MINISIEM_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
   echo "$MINISIEM_API_KEY"
   ```

   ```powershell
   # Windows PowerShell
   $env:MINISIEM_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(24))"
   $env:MINISIEM_API_KEY
   ```

   If you start the server without a key, it generates one and prints it. That key only lasts for
   that run.

2. Start the server:

   ```bash
   python -m minisiem
   ```

   | Option | Default | Meaning |
   |---|---|---|
   | `--host` | `127.0.0.1` | Address to listen on. Use a LAN or Tailscale IP (or `0.0.0.0`) so other machines can send logs |
   | `--port` | `8000` | Port to listen on |
   | `--db` | `minisiem.db` | SQLite database file, created if missing |
   | `--rules` | none | TOML file that overrides rule thresholds (see [Detection rules](#detection-rules)) |

   Example for remote agents over Tailscale:

   ```bash
   python -m minisiem --host 100.77.177.65 --port 8000 --db siem.db --rules rules.toml
   ```

Stop the server with `Ctrl+C`. Events and alerts stay in the database file. Delete it to start fresh.

## Open the dashboard

Browse to `http://<host>:<port>/#key=<your API key>`, for example
`http://127.0.0.1:8000/#key=abc123`. The dashboard saves the key for the browser tab and removes it
from the address bar. Open the page without `#key=` and it asks for the key.

The page refreshes every 5 seconds. Click an alert row to see its evidence (the raw log lines).
The severity, IP and time period filters apply to both tables; the event type filter applies to events.

## Try it on one machine (replay demo)

Sample logs in `samples/` contain a brute-force attack, password spraying, a login after failed
attempts, sudo failures, a port scan, web attacks and content discovery. With the server running,
open a second terminal, activate the virtual environment, set the same `MINISIEM_API_KEY`, then run:

```bash
python tools/replay.py                     # sends samples/*.log to http://127.0.0.1:8000
python tools/e2e_check.py --expect brute_force,password_spray,success_after_failures,invalid_user,port_scan,suspicious_http,http_error_flood,sudo_failures
```

`e2e_check.py` lists the alerts and prints `PASS` or `FAIL` for each expected rule. It exits `1` if
any rule is missing. Both scripts take `--server http://host:port` for a server that is not local.
The sample logs are dated 10 Nov 2026, so set the dashboard's time period filter to "all time".

## Monitor other machines

### 1. Make the server reachable

Start the server with `--host` set to an address the monitored hosts can reach (see
[Run the server](#run-the-server)). On Windows, allow the port through the firewall if agents
cannot connect (run PowerShell as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Mini SIEM" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

Check from the monitored host: `curl http://<server>:8000/` should print the dashboard HTML.

### 2. Prepare each Linux host

```bash
# read sshd, sudo and kernel messages from the system journal (log out and back in afterwards)
sudo usermod -aG adm,systemd-journal $USER
# log blocked connections, needed for port-scan detection
sudo ufw logging low
```

### 3. Run the agent

Copy `minisiem/agent.py` to the host. It needs nothing else installed.

```bash
export MINISIEM_API_KEY=<your API key>
python3 agent.py --server http://<server>:8000 --journal \
    --file web:/var/log/nginx/access.log \
    --file firewall:/var/log/ufw.log
```

| Option | Meaning |
|---|---|
| `--server URL` | Mini SIEM server, e.g. `http://100.77.177.65:8000` (required) |
| `--journal` | Follow journald for sshd, sudo and kernel (ufw/iptables) messages |
| `--file KIND:PATH` | Tail a log file; `KIND` is `auth`, `web` or `firewall`. Repeatable |
| `--from-start` | Read files from the beginning instead of only new lines |
| `--host NAME` | Host name reported with the logs (default: this machine's name) |

Use `--journal` on hosts with systemd (Debian 12+, Ubuntu, Fedora). Use `--file auth:/var/log/auth.log`
(Debian/Ubuntu) or `--file auth:/var/log/secure` (RHEL) on hosts with a classic syslog file. The
agent sends batches every 2 seconds and keeps up to 20,000 records in memory while the server is
unreachable.

### 4. Optional: run the agent as a systemd service

```ini
# /etc/systemd/system/minisiem-agent.service
[Unit]
Description=Mini SIEM agent
After=network-online.target

[Service]
User=lakshya
EnvironmentFile=/etc/minisiem-agent.env
ExecStart=/usr/bin/python3 /opt/minisiem/agent.py --server http://100.77.177.65:8000 --journal
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Put `MINISIEM_API_KEY=<your API key>` in `/etc/minisiem-agent.env` and make it readable only by
root (`sudo chmod 600 /etc/minisiem-agent.env`). Change `User=` to an account in the `adm` and
`systemd-journal` groups. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now minisiem-agent
journalctl -u minisiem-agent -f
```

### Custom application events

Applications can post their own events to `/api/ingest` without the agent:

```bash
curl -X POST http://<server>:8000/api/ingest \
  -H "Authorization: Bearer $MINISIEM_API_KEY" -H "Content-Type: application/json" \
  -d '{"host": "app01", "records": [{"kind": "event", "event": {
        "timestamp": "2026-11-10T10:00:00Z", "event_type": "app_login_failed",
        "src_ip": "10.1.1.1", "user": "alice", "severity": "low"}}]}'
```

## Lab attack simulation

`tools/attack.py` and `tools/demo_web.py` reproduce the attacks the rules detect.
**Only run them against machines you own or are allowed to test.**

On the monitored host, start the demo web app and add its log to the agent:

```bash
python3 demo_web.py --port 8080 --log ~/demo-access.log
python3 agent.py --server http://<server>:8000 --journal --file web:$HOME/demo-access.log
```

On the attacking machine (inside the virtual environment):

```bash
pip install paramiko                                    # needed for --ssh only
python tools/attack.py --target <host LAN IP> --scan    # TCP connect scan of ports 1-1024
python tools/attack.py --target <host IP> --ssh 8       # 8 failed SSH password logins
python tools/attack.py --target <host IP> --http 8080   # SQLi, XSS, traversal, .env, 25 x 404 with a scanner user agent
python tools/e2e_check.py --server http://<server>:8000 \
    --expect port_scan,brute_force,password_spray,invalid_user,suspicious_http,http_error_flood --wait 60
```

A successful SSH key login from the attacking address within 10 minutes of the failed logins also
raises the critical `success_after_failures` alert.

Pitfalls found while testing between a Windows server/attacker and a Debian 13 host:

- **ufw limits its logging.** Every level except `full` logs about 3 lines per minute after a burst of
  10, so a fast port scan leaves too few lines for `port_scan`. Run `sudo ufw logging full` during a
  scan test and `sudo ufw logging low` afterwards.
- **Tailscale traffic skips ufw**, so a scan of a Tailscale IP is never logged. Scan the LAN address.
- **OpenSSH 9.8+ refuses connections** (`PerSourcePenalties`) from an address after a few failed
  logins. The failures logged before that are enough for `brute_force` and `password_spray`. Attack
  from a different address than the one you manage the host from, or you lock yourself out for a while.

Verified live on 2026-11-10: `port_scan`, `brute_force`, `password_spray`, `invalid_user`,
`success_after_failures`, `suspicious_http`, `http_error_flood`. `sudo_failures` is covered by the
replay tests only.

## Detection rules

| Rule | Logic (defaults) | Severity | ATT&CK |
|---|---|---|---|
| `brute_force` | >= 5 failed logins from one IP in 60 s | high | T1110.001 |
| `password_spray` | >= 5 distinct usernames tried from one IP in 5 min | high | T1110.003 |
| `success_after_failures` | successful login from an IP with >= 3 failures in 10 min | critical | T1078 |
| `invalid_user` | login attempt as a non-existent user or as root | medium | T1078 |
| `port_scan` | >= 10 distinct blocked destination ports from one IP in 60 s | high | T1046 |
| `suspicious_http` | SQLi, XSS, path traversal, sensitive file or scanner user agent | medium / high | T1190 |
| `http_error_flood` | >= 20 responses 401/403/404 to one IP in 60 s | medium | T1595 |
| `sudo_failures` | >= 3 failed sudo attempts by one user on one host in 5 min | medium | T1548.003 |

The same rule for the same key (IP or user) alerts at most once every `suppress_seconds` (300 s by
default). Rules use the time in each event, not the clock time, so replayed logs give the same alerts
as live ones.

To change thresholds, create a TOML file and pass it with `--rules`. Only the values you list change:

```toml
suppress_seconds = 120

[brute_force]
threshold = 3
window = 120

[port_scan]
threshold = 20
```

Rule names are `brute_force`, `password_spray`, `success_after_failures`, `port_scan`,
`http_error_flood` and `sudo_failures`. Each takes `window` (seconds) and `threshold`. An unknown
name stops the server with an error.

## API reference

Every `/api/*` endpoint needs the header `Authorization: Bearer <MINISIEM_API_KEY>`. A missing or
wrong key gives HTTP 401.

| Method and path | Purpose |
|---|---|
| `POST /api/ingest` | Send records: `{"host": "...", "records": [...]}`, up to 5,000 per request. Returns `{"accepted", "skipped", "alerts"}` |
| `GET /api/events` | Events, newest first. Filters: `severity`, `event_type`, `source`, `ip`, `host`, `since`, `until`, `limit` (1-1000, default 100) |
| `GET /api/alerts` | Alerts, newest first. Filters: `severity`, `rule`, `ip`, `host`, `since`, `until`, `limit` |
| `GET /api/stats` | Totals, alerts by severity, top IPs, attack types, events by source, per-minute timelines |
| `GET /` | Dashboard |

Record kinds for `/api/ingest`:

| `kind` | Field | Content |
|---|---|---|
| `auth` | `line` | One auth.log / secure line |
| `web` | `line` | One Apache/Nginx access log line (combined or common format) |
| `firewall` | `line` | One UFW/iptables kernel log line |
| `journal` | `entry` | One `journalctl -o json` object |
| `event` | `event` | Custom event; needs `timestamp` and `event_type`, other event fields optional |

`since` and `until` take ISO 8601 times, e.g. `2026-11-10T09:00:00Z`. Interactive API docs are at
`http://<server>:8000/docs`.

## Project layout

```
minisiem/
  __main__.py                 server entry point (python -m minisiem)
  api.py                      FastAPI app: ingest, query, dashboard
  event.py                    normalized Event schema
  alerts.py                   Alert record
  db.py                       SQLite storage and queries
  agent.py                    collection agent (standard library only)
  parsers/auth.py             sshd / sudo, from auth.log or journald
  parsers/web.py              Apache / Nginx access logs
  parsers/firewall.py         UFW / iptables kernel logs
  detection/engine.py         sliding-window rules and alert suppression
  detection/http_signatures.py  SQLi / XSS / traversal / sensitive file / scanner signatures
  dashboard/                  index.html, app.js
samples/                      sample attack logs for the replay demo
tools/replay.py               send samples to a server
tools/e2e_check.py            check that expected alerts exist
tools/attack.py               lab attack simulator
tools/demo_web.py             demo web app that writes an access log
tests/                        pytest suite
PLAN.md                       build plan and work split
```

## Tests

```bash
pytest -q
```

The suite covers the parsers, every detection rule, API authentication and validation, and a full
replay of `samples/` that must raise all 8 rules. GitHub Actions runs it on Ubuntu and Windows on
every push. The parser and signature tests (`tests/test_web_parser.py`, `tests/test_firewall_parser.py`,
`tests/test_http_signatures.py`) also run with the standard library alone:

```bash
python -m unittest tests.test_web_parser tests.test_firewall_parser tests.test_http_signatures -v
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'minisiem'` when running `tools/*.py` | Activate the virtual environment and run `pip install -e .` |
| Dashboard shows "invalid API key" | Reload the page and enter the server's key, or open it with `#key=<key>` |
| Agent prints `server unreachable` | Check the `--server` URL, that the server's `--host` is not `127.0.0.1`, and the server's firewall |
| Agent prints `server rejected batch: HTTP 401` | The agent's `MINISIEM_API_KEY` differs from the server's |
| No sshd or firewall events from `--journal` | Add the agent's user to `adm` and `systemd-journal`, then log in again (`id` must list them) |
| No firewall events at all | Run `sudo ufw logging low`, and make sure the traffic does not arrive over Tailscale |
| A port scan raises no `port_scan` alert | ufw rate limiting; see [Lab attack simulation](#lab-attack-simulation) |
| No alerts in the dashboard after a replay | Set the time period filter to "all time"; the samples are dated 10 Nov 2026 |

## Security notes

- Every API endpoint needs the API key. The server compares keys in constant time and generates
  a random key when none is set.
- Traffic is plain HTTP. Run it over Tailscale/WireGuard or a trusted LAN, or put it behind a
  TLS reverse proxy. Do not expose the server to the internet.
- Log text is attacker-controlled, so the dashboard shows it as text, never as HTML.
- Ingest requests are validated: record kinds and line lengths are checked, custom events must have
  valid fields (severity, ports, sizes), and each request is limited to 5,000 records.

Future scope: PostgreSQL, machine-learning anomaly detection, email or chat notifications,
threat-intelligence and IP reputation lookups, role-based access control, a Windows Event Log collector.
