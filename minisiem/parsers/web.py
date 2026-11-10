"""Apache / Nginx access log parser (combined and common log format).

TASK W1 (HiveMind worker): implement parse_line(). Standard library only.
Spec (tests/test_web_parser.py is the source of truth):

Input examples:
  combined: 203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://x/" "Mozilla/4.08"
  common:   203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326

Return an Event with:
  timestamp  timezone-aware datetime converted to UTC
  source     "web"
  event_type "http_request"
  src_ip     client address (IPv4 or IPv6)
  user       auth user, or None when "-"
  action     HTTP method, or None when the request line is not "METHOD PATH PROTOCOL"
  status     HTTP status code as a string, e.g. "404"
  severity   "info"
  host       the `host` argument
  raw        the input line with the trailing newline stripped
  meta       {"path": str | None, "protocol": str | None, "bytes": int (0 when "-"),
              "referer": str | None, "user_agent": str | None, "request": raw request string}
              referer / user_agent are None when absent or "-".

Return None for blank or malformed lines. Never raise on bad input.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from minisiem.event import Event


def parse_line(line: str, host: str | None = None) -> Event | None:
    if not line or not line.strip():
        return None

    # Regex pattern for Combined/Common Log Format
    # 1: IP, 2: Ident (ignored), 3: User, 4: Timestamp, 5: Request, 6: Status, 7: Bytes, 8: Referer, 9: User Agent
    pattern = r'^(\S+) \S+ (\S+) \[(.*?)\] "(.*?)" (\d{3}) (\S+)(?: "(.*?)" "(.*?)")?$'
    
    try:
        match = re.match(pattern, line.rstrip("\n"))
        if not match:
            return None

        src_ip = match.group(1)
        user_raw = match.group(2)
        ts_raw = match.group(3)
        request_raw = match.group(4)
        status = match.group(5)
        bytes_raw = match.group(6)
        referer_raw = match.group(7)
        ua_raw = match.group(8)

        # Parse Timestamp: 10/Oct/2000:13:55:36 -0700
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)

        # Parse User
        user = None if user_raw == "-" else user_raw

        # Parse Request Line (Method Path Protocol)
        action = None
        path = None
        protocol = None
        request_parts = request_raw.split(" ")
        if len(request_parts) == 3:
            action = request_parts[0]
            path = request_parts[1]
            protocol = request_parts[2]

        # Parse Bytes
        try:
            bytes_val = int(bytes_raw) if bytes_raw != "-" else 0
        except ValueError:
            bytes_val = 0

        # Parse Referer and User Agent
        referer = None if referer_raw == "-" or referer_raw is None else referer_raw
        user_agent = None if ua_raw == "-" or ua_raw is None else ua_raw

        meta = {
            "path": path,
            "protocol": protocol,
            "bytes": bytes_val,
            "referer": referer,
            "user_agent": user_agent,
            "request": request_raw,
        }

        return Event(
            timestamp=ts,
            source="web",
            event_type="http_request",
            src_ip=src_ip,
            user=user,
            action=action,
            status=status,
            severity="info",
            host=host,
            raw=line.rstrip("\n"),
            meta=meta,
        )

    except Exception:
        return None
