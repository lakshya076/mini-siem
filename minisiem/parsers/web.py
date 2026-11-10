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

from minisiem.event import Event


def parse_line(line: str, host: str | None = None) -> Event | None:
    raise NotImplementedError("W1: implement web access log parsing")
