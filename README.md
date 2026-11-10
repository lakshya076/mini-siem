# Mini SIEM

A lightweight Security Information and Event Management system for real-time threat detection
and monitoring. Agents collect system and application logs, the server normalizes them into one
event schema, runs rule-based detection, raises alerts and shows everything on a web dashboard.

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

## Detection rules

| Rule | Logic (defaults, override in a TOML file) | Severity | ATT&CK |
|---|---|---|---|
| `brute_force` | >= 5 failed logins from one IP in 60 s | high | T1110.001 |
| `password_spray` | >= 5 distinct usernames tried from one IP in 5 min | high | T1110.003 |
| `success_after_failures` | successful login from an IP with >= 3 failures in 10 min | critical | T1078 |
| `invalid_user` | login attempt as a non-existent user or as root | medium | T1078 |
| `port_scan` | >= 10 distinct blocked destination ports from one IP in 60 s | high | T1046 |
| `suspicious_http` | SQLi, XSS, path traversal, sensitive file or scanner user agent | medium / high | T1190 |
| `http_error_flood` | >= 20 responses 401/403/404 to one IP in 60 s | medium | T1595 |
| `sudo_failures` | >= 3 failed sudo attempts by one user on one host in 5 min | medium | T1548.003 |

The same rule for the same key (IP, user) alerts at most once per 5 minutes. Windows use event
time, so replayed logs give the same alerts as live ones. Example override file:

```toml
suppress_seconds = 120
[brute_force]
threshold = 3
```

## Quick start (one machine)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux: source .venv/bin/activate
pip install -e ".[dev]"
export MINISIEM_API_KEY=change-me          # PowerShell: $env:MINISIEM_API_KEY="change-me"
python -m minisiem                          # http://127.0.0.1:8000/#key=change-me
python tools/replay.py                      # in a second shell: replays samples/*.log
python tools/e2e_check.py --expect brute_force,password_spray,success_after_failures,port_scan,suspicious_http,http_error_flood,sudo_failures
```

## Monitoring other machines

On the server, bind to an address the hosts can reach (a Tailscale or LAN IP):

```bash
python -m minisiem --host 100.x.y.z --port 8000 [--rules rules.toml]
```

On each Linux host, copy `minisiem/agent.py` (standard library only, nothing to install):

```bash
export MINISIEM_API_KEY=change-me
python3 agent.py --server http://100.x.y.z:8000 --journal \
    --file web:/var/log/nginx/access.log --file firewall:/var/log/ufw.log
```

`--journal` follows sshd, sudo and kernel (ufw/iptables) messages. Reading the system journal needs
the user in the `adm` or `systemd-journal` group. ufw only logs when `sudo ufw logging on` is set.
Agents can also post custom application events (`{"kind": "event", "event": {...}}`) to `/api/ingest`.

## Lab attack simulation

Only run these against machines you own or are allowed to test.

```bash
python3 tools/demo_web.py --port 8080 --log /tmp/demo-access.log     # on the monitored host
pip install paramiko                                                  # on the attacker, for --ssh
python tools/attack.py --target <host> --scan --ssh 8 --http 8080
python tools/e2e_check.py --server http://<server>:8000 --expect brute_force,suspicious_http --wait 60
```

Things found while testing between two machines (Windows server/attacker, Debian 13 monitored host):

- ufw rate-limits its log lines at every level except `full` (about 3 per minute after a burst of 10),
  so a fast port scan leaves only a few log lines and `port_scan` cannot fire. Use
  `sudo ufw logging full` during a scan test, then set it back to `low`.
- Tailscale accepts traffic on `tailscale0` before ufw sees it, so scans over a Tailscale IP are not
  logged at all. Scan the host's LAN address instead.
- OpenSSH 9.8+ (`PerSourcePenalties`) starts refusing connections from an address after a few failed
  logins. The failures before that are still logged, and enough for `brute_force` and `password_spray`.
  Attack from a different address than the one you administer the host from.

Verified live on 2026-11-10: `port_scan`, `brute_force`, `password_spray`, `invalid_user`,
`success_after_failures`, `suspicious_http`, `http_error_flood`. `sudo_failures` is covered by the
replay tests only.

## Security notes

- Every `/api/*` endpoint needs `Authorization: Bearer <MINISIEM_API_KEY>`; the server generates a
  key if none is set. The dashboard keeps the key in session storage.
- Traffic is plain HTTP; run it over Tailscale/WireGuard or put it behind a TLS reverse proxy.
- Log text is attacker-controlled, so the dashboard renders it as text, never as HTML.

## Development

```bash
pytest
```

See [PLAN.md](PLAN.md) for the build plan and how the work was split with a HiveMind worker.
Future scope: PostgreSQL, ML anomaly detection, notifications, threat intelligence, RBAC, Windows Event Log collector.
