"""Linux authentication log parser: sshd and sudo, from auth.log lines or journald JSON entries.

Event types produced:
  auth_failure       failed password / publickey / keyboard-interactive login (sshd)
  auth_success       accepted login (sshd)
  auth_invalid_user  login attempt for a user that does not exist (sshd)
  sudo_failure       wrong sudo password (pam_unix(sudo:auth))
  sudo_command       sudo command run
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from minisiem.event import Event

CLASSIC = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([\w.@-]+)(?:\[\d+\])?: (.*)$")
RFC3339 = re.compile(r"^(\d{4}-\d\d-\d\dT\S+) (\S+) ([\w.@-]+)(?:\[\d+\])?: (.*)$")

SSH_FAILED = re.compile(
    r"^Failed (password|publickey|keyboard-interactive/pam|none) for (invalid user )?(\S*) from (\S+) port (\d+)"
)
SSH_ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
SSH_INVALID = re.compile(r"^Invalid user (\S*) from (\S+) port (\d+)")
SUDO_FAIL = re.compile(r"^pam_unix\(sudo:auth\): authentication failure;.*?\buser=(\S+)")
# "user : TTY=.. ; PWD=.. ; USER=root ; COMMAND=.." optionally preceded by a reason such as "user NOT in sudoers ; "
SUDO_LINE = re.compile(r"^\s*(\S+) : (?:(.*?) ; )?TTY=\S+ ; PWD=.*? ; USER=(\S+) ; COMMAND=(.*)$")

SSHD = {"sshd", "sshd-session"}  # OpenSSH >= 9.8 logs auth from sshd-session


def parse_message(program: str, message: str, timestamp: datetime,
                  host: str | None = None, raw: str = "") -> Event | None:
    """Turn one sshd / sudo message into an Event; None for messages we do not track."""
    base = dict(timestamp=timestamp, source="auth", host=host, raw=raw or message)
    if program in SSHD:
        if m := SSH_FAILED.match(message):
            method, invalid, user, ip, port = m.groups()
            return Event(event_type="auth_failure", user=user, src_ip=ip, src_port=int(port), action="login",
                         status="failure", meta={"method": method, "invalid_user": bool(invalid),
                                                 "service": "ssh"}, **base)
        if m := SSH_ACCEPTED.match(message):
            method, user, ip, port = m.groups()
            return Event(event_type="auth_success", user=user, src_ip=ip, src_port=int(port), action="login",
                         status="success", meta={"method": method, "service": "ssh"}, **base)
        if m := SSH_INVALID.match(message):
            user, ip, port = m.groups()
            return Event(event_type="auth_invalid_user", user=user, src_ip=ip, src_port=int(port),
                         action="login", status="failure", meta={"service": "ssh"}, **base)
    elif program == "sudo":
        if m := SUDO_FAIL.match(message):
            return Event(event_type="sudo_failure", user=m[1], action="sudo", status="failure",
                         meta={"service": "sudo"}, **base)
        if m := SUDO_LINE.match(message):
            user, reason, target, command = m.groups()
            meta = {"service": "sudo", "target_user": target, "command": command}
            if reason is None:
                return Event(event_type="sudo_command", user=user, action="sudo", status="success", meta=meta, **base)
            if "not in sudoers" in reason.lower() or "not allowed" in reason.lower():
                return Event(event_type="sudo_failure", user=user, action="sudo", status="failure",
                             meta={**meta, "reason": reason}, **base)
            # "N incorrect password attempts" repeats the pam_unix failures already counted
    return None


def parse_line(line: str, host: str | None = None, year: int | None = None) -> Event | None:
    """Parse one /var/log/auth.log (or /var/log/secure) line."""
    raw = line.rstrip("\n")
    if m := CLASSIC.match(raw):
        try:
            ts = datetime.strptime(f"{year or datetime.now(timezone.utc).year} {m[1]}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        ts = ts.replace(tzinfo=timezone.utc)  # shortcut: syslog has no zone, assumes UTC; use RFC 3339 logs if not
    elif m := RFC3339.match(raw):
        try:
            ts = datetime.fromisoformat(m[1]).astimezone(timezone.utc)
        except ValueError:
            return None
    else:
        return None
    return parse_message(m[3], m[4], ts, host=m[2], raw=raw)


def parse_journal(entry: dict) -> Event | None:
    """Parse one `journalctl -o json` entry for sshd or sudo."""
    try:
        ts = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000, tz=timezone.utc)
    except (KeyError, ValueError, TypeError):
        return None
    message = entry.get("MESSAGE")
    if not isinstance(message, str):  # journald sends non-UTF-8 messages as byte arrays
        return None
    program = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or ""
    return parse_message(program, message, ts, host=entry.get("_HOSTNAME"), raw=message)
