"""Detection rules over a stream of Events, using sliding time windows keyed by IP or user.

Windows run on event time, not wall-clock time, so replayed logs produce the same alerts as live ones.
"""
from __future__ import annotations

import tomllib
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from minisiem.alerts import Alert
from minisiem.detection.http_signatures import classify
from minisiem.event import Event

DEFAULTS: dict = {
    "suppress_seconds": 300,  # same rule + same key alerts at most once per this many seconds
    "brute_force": {"window": 60, "threshold": 5},
    "password_spray": {"window": 300, "threshold": 5},
    "success_after_failures": {"window": 600, "threshold": 3},
    "port_scan": {"window": 60, "threshold": 10},
    "http_error_flood": {"window": 60, "threshold": 20},
    "sudo_failures": {"window": 300, "threshold": 3},
}

HIGH_HTTP = {"sqli", "path_traversal"}
MAX_EVIDENCE = 10


def load_config(path: str | Path | None = None) -> dict:
    """DEFAULTS overlaid with the rule tables of a TOML file, if given."""
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    if path:
        with open(path, "rb") as f:
            for key, value in tomllib.load(f).items():
                if key not in cfg:
                    raise ValueError(f"unknown rule in {path}: {key}")
                if isinstance(value, dict):
                    cfg[key].update(value)
                else:
                    cfg[key] = value
    return cfg


class Window:
    """Per-key deque of (timestamp, value, raw line) limited to the last `seconds`."""

    def __init__(self, seconds: int):
        self.span = timedelta(seconds=seconds)
        # shortcut: keys are never evicted, fine for a lab; add periodic cleanup for long-running busy hosts
        self.data: dict = defaultdict(deque)

    def add(self, key, ev: Event, value=None) -> deque:
        q = self.data[key]
        q.append((ev.timestamp, value, ev.raw))
        return self.prune(key, ev)

    def prune(self, key, ev: Event) -> deque:
        q = self.data[key]
        while q and q[0][0] < ev.timestamp - self.span:
            q.popleft()
        return q


def _raws(q) -> list[str]:
    return [raw for _, _, raw in list(q)[-MAX_EVIDENCE:]]


class Detector:
    def __init__(self, config: dict | None = None):
        self.cfg = config or load_config()
        self.win = {name: Window(c["window"]) for name, c in self.cfg.items() if isinstance(c, dict)}
        self.suppress = timedelta(seconds=self.cfg["suppress_seconds"])
        self.last_alert: dict = {}

    def _threshold(self, rule: str) -> int:
        return self.cfg[rule]["threshold"]

    def _emit(self, out: list, key, ev: Event, **fields) -> None:
        """Append an Alert unless the same rule fired for the same key within the suppression window."""
        k = (fields["rule"], key)
        last = self.last_alert.get(k)
        if last is not None and ev.timestamp - last < self.suppress:
            return
        self.last_alert[k] = ev.timestamp
        out.append(Alert(timestamp=ev.timestamp, src_ip=ev.src_ip, host=ev.host, **fields))

    def process(self, ev: Event) -> list[Alert]:
        out: list[Alert] = []
        t, ip = ev.event_type, ev.src_ip

        if t == "auth_failure" and ip:
            q = self.win["brute_force"].add(ip, ev)
            if len(q) >= self._threshold("brute_force"):
                self._emit(out, ip, ev, rule="brute_force", title="Brute-force attack", severity="high",
                           mitre="T1110.001", user=ev.user, evidence=_raws(q),
                           description=f"{len(q)} failed logins from {ip} within "
                                       f"{self.cfg['brute_force']['window']}s")
            self.win["success_after_failures"].add(ip, ev)

        if t in ("auth_failure", "auth_invalid_user") and ip:
            q = self.win["password_spray"].add(ip, ev, ev.user)
            users = {u for _, u, _ in q if u}
            if len(users) >= self._threshold("password_spray"):
                self._emit(out, ip, ev, rule="password_spray", title="Password spraying", severity="high",
                           mitre="T1110.003", evidence=_raws(q),
                           description=f"{ip} tried {len(users)} different usernames within "
                                       f"{self.cfg['password_spray']['window']}s: {', '.join(sorted(users))}")

        if t == "auth_invalid_user" or (t == "auth_failure" and ev.user == "root"):
            what = "non-existent user" if t == "auth_invalid_user" else "root"
            self._emit(out, (ip, ev.user), ev, rule="invalid_user", title="Invalid or root login attempt",
                       severity="medium", mitre="T1078", user=ev.user, evidence=[ev.raw],
                       description=f"Login attempt as {what} '{ev.user}' from {ip}")

        if t == "auth_success" and ip:
            q = self.win["success_after_failures"].prune(ip, ev)
            if len(q) >= self._threshold("success_after_failures"):
                self._emit(out, ip, ev, rule="success_after_failures", title="Suspicious successful login",
                           severity="critical", mitre="T1078", user=ev.user, evidence=_raws(q) + [ev.raw],
                           description=f"User '{ev.user}' logged in from {ip} after {len(q)} failed "
                                       f"attempts from the same address (possible compromised account)")

        if ev.source == "firewall" and ip and ev.dst_port is not None and ev.action != "allow":
            q = self.win["port_scan"].add(ip, ev, ev.dst_port)
            ports = {p for _, p, _ in q}
            if len(ports) >= self._threshold("port_scan"):
                self._emit(out, ip, ev, rule="port_scan", title="Port scan", severity="high", mitre="T1046",
                           evidence=_raws(q),
                           description=f"{ip} probed {len(ports)} distinct ports on {ev.dst_ip or ev.host} within "
                                       f"{self.cfg['port_scan']['window']}s")

        if t == "http_request":
            cats = classify(ev.meta.get("path"), ev.meta.get("user_agent"))
            if cats:
                self._emit(out, (ip, tuple(cats)), ev, rule="suspicious_http", title="Suspicious HTTP request",
                           severity="high" if HIGH_HTTP & set(cats) else "medium", mitre="T1190",
                           evidence=[ev.raw],
                           description=f"{', '.join(cats)} pattern in request from {ip}: "
                                       f"{(ev.meta.get('request') or '')[:200]}")
            if ev.status in ("401", "403", "404") and ip:
                q = self.win["http_error_flood"].add(ip, ev)
                if len(q) >= self._threshold("http_error_flood"):
                    self._emit(out, ip, ev, rule="http_error_flood", title="Abnormal HTTP error rate",
                               severity="medium", mitre="T1595", evidence=_raws(q),
                               description=f"{len(q)} 401/403/404 responses to {ip} within "
                                           f"{self.cfg['http_error_flood']['window']}s (content discovery?)")

        if t == "sudo_failure":
            key = (ev.host, ev.user)
            q = self.win["sudo_failures"].add(key, ev)
            if len(q) >= self._threshold("sudo_failures"):
                self._emit(out, key, ev, rule="sudo_failures", title="Repeated sudo failures", severity="medium",
                           mitre="T1548.003", user=ev.user, evidence=_raws(q),
                           description=f"{len(q)} failed sudo attempts by '{ev.user}' on {ev.host} within "
                                       f"{self.cfg['sudo_failures']['window']}s")
        return out
