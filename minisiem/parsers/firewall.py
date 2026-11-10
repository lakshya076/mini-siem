"""UFW / iptables kernel LOG line parser.

TASK W2 (HiveMind worker): implement parse_line(). Standard library only.
Spec (tests/test_firewall_parser.py is the source of truth):

Accepted line shapes:
  1. classic syslog prefix:
     Nov 10 12:34:56 ari kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=.. SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=40000 DPT=22 ... SYN URGP=0
  2. RFC 3339 syslog prefix (Debian rsyslog default):
     2026-11-10T12:34:56.123456+05:30 ari kernel: [UFW BLOCK] IN=eth0 ...
  3. bare kernel message (e.g. from journald), no timestamp / host prefix:
     [UFW BLOCK] IN=eth0 OUT= SRC=... DST=...
  The kernel uptime stamp "[12345.678901]" may or may not be present.

Timestamp:
  shape 1: year from the `year` argument (default: current UTC year), time taken as UTC.
  shape 2: parsed offset converted to UTC.
  shape 3: `default_time` if given, else the current UTC time.

Action, from the log prefix (case-insensitive):
  "[UFW BLOCK]" / "[UFW LIMIT BLOCK]" / prefixes containing DROP, REJECT or BLOCK -> "block"
  "[UFW ALLOW]" / prefixes containing ACCEPT or ALLOW                              -> "allow"
  "[UFW AUDIT]"                                                                    -> "audit"
  anything else                                                                    -> "log"

Return an Event with:
  source "firewall", event_type f"firewall_{action}", action, severity "info",
  src_ip (SRC=), dst_ip (DST=), src_port int (SPT=) or None, dst_port int (DPT=) or None,
  host: syslog hostname when present, else the `host` argument,
  raw: input line with trailing newline stripped,
  meta {"proto": str | None, "in": str | None, "out": str | None, "flags": list[str]}
       "in"/"out" are None when empty (e.g. "OUT="). "flags" lists the bare TCP flag words
       present as whole tokens, in the order they appear, from: CWR ECE URG ACK PSH RST SYN FIN.
       ("URGP=0" is a field, not the URG flag.)

Return None for blank lines and lines with no SRC= field. Never raise on bad input.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

from minisiem.event import Event

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_FLAG_WORDS = {"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}


def parse_line(
    line: str,
    host: str | None = None,
    year: int | None = None,
    default_time: datetime | None = None,
) -> Event | None:
    """Parse a single UFW/iptables kernel LOG line into an Event."""
    try:
        raw = line.rstrip("\n")

        if not line.strip():
            return None

        timestamp: datetime
        resolved_host: str | None = host
        rest: str = line

        # Shape 1: classic syslog prefix "Mon DD HH:MM:SS hostname ..."
        m = re.match(
            r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+',
            line,
        )
        if m:
            mon, day, hh, mm, ss, resolved_host = m.groups()
            ts_year = year if year is not None else datetime.now(timezone.utc).year
            timestamp = datetime(
                ts_year,
                _MONTHS[mon],
                int(day),
                int(hh),
                int(mm),
                int(ss),
                tzinfo=timezone.utc,
            )
            rest = line[m.end():]

        else:
            # Shape 2: RFC 3339 syslog prefix "2026-11-10T12:34:56.123456+05:30 hostname ..."
            m = re.match(
                r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\s+(\S+)\s+',
                line,
            )
            if m:
                ts_str, resolved_host = m.groups()
                timestamp = _parse_rfc3339(ts_str)
                rest = line[m.end():]
            else:
                # Shape 3: bare kernel message
                if default_time is not None:
                    timestamp = default_time
                else:
                    timestamp = datetime.now(timezone.utc)
                rest = line

        # The log prefix is everything before the first "IN=" token.
        idx = rest.find("IN=")
        if idx == -1:
            prefix = rest
            body = ""
        else:
            prefix = rest[:idx]
            body = rest[idx:]

        if "SRC=" not in rest:
            return None

        fields: dict[str, str] = {}
        flags: list[str] = []
        for tok in body.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                fields[k] = v
            elif tok in _FLAG_WORDS:
                flags.append(tok)

        src_ip = fields.get("SRC")
        dst_ip = fields.get("DST")

        src_port = None
        if "SPT" in fields:
            try:
                src_port = int(fields["SPT"])
            except ValueError:
                src_port = None

        dst_port = None
        if "DPT" in fields:
            try:
                dst_port = int(fields["DPT"])
            except ValueError:
                dst_port = None

        proto = fields.get("PROTO")
        in_iface = fields.get("IN") or None
        out_iface = fields.get("OUT") or None

        prefix_lower = prefix.lower()
        if "audit" in prefix_lower:
            action = "audit"
        elif any(kw in prefix_lower for kw in ("drop", "reject", "block")):
            action = "block"
        elif any(kw in prefix_lower for kw in ("accept", "allow")):
            action = "allow"
        else:
            action = "log"

        return Event(
            timestamp=timestamp,
            source="firewall",
            event_type=f"firewall_{action}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            action=action,
            severity="info",
            host=resolved_host,
            raw=raw,
            meta={
                "proto": proto,
                "in": in_iface,
                "out": out_iface,
                "flags": flags,
            },
        )
    except Exception:
        return None


def _parse_rfc3339(ts_str: str) -> datetime:
    """Parse an RFC 3339 timestamp with offset and return a UTC datetime."""
    offset_str = ts_str[-6:]
    ts_part = ts_str[:-6]
    sign = 1 if offset_str[0] == "+" else -1
    off_hours = int(offset_str[1:3])
    off_minutes = int(offset_str[4:6])
    offset = timedelta(hours=sign * off_hours, minutes=sign * off_minutes)

    if "." in ts_part:
        dt = datetime.strptime(ts_part, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        dt = datetime.strptime(ts_part, "%Y-%m-%dT%H:%M:%S")

    dt_utc = dt - offset
    return dt_utc.replace(tzinfo=timezone.utc)
