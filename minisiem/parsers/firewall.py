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

from datetime import datetime

from minisiem.event import Event


def parse_line(
    line: str,
    host: str | None = None,
    year: int | None = None,
    default_time: datetime | None = None,
) -> Event | None:
    raise NotImplementedError("W2: implement firewall log parsing")
