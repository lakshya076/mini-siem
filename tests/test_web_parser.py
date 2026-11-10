"""Acceptance tests for task W1 (minisiem/parsers/web.py). Stdlib unittest only.

Run: python3 -m unittest tests.test_web_parser -v
"""
import unittest
from datetime import datetime, timezone

from minisiem.parsers.web import parse_line

COMBINED = (
    '203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 '
    '"http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"\n'
)
COMMON = '198.51.100.4 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401 -'


class TestCombined(unittest.TestCase):
    def setUp(self):
        self.ev = parse_line(COMBINED, host="web01")

    def test_core_fields(self):
        ev = self.ev
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source, "web")
        self.assertEqual(ev.event_type, "http_request")
        self.assertEqual(ev.src_ip, "203.0.113.7")
        self.assertEqual(ev.user, "frank")
        self.assertEqual(ev.action, "GET")
        self.assertEqual(ev.status, "200")
        self.assertEqual(ev.severity, "info")
        self.assertEqual(ev.host, "web01")

    def test_timestamp_utc(self):
        self.assertEqual(self.ev.timestamp, datetime(2000, 10, 10, 20, 55, 36, tzinfo=timezone.utc))
        self.assertEqual(self.ev.timestamp.utcoffset().total_seconds(), 0)

    def test_meta(self):
        m = self.ev.meta
        self.assertEqual(m["path"], "/apache_pb.gif")
        self.assertEqual(m["protocol"], "HTTP/1.0")
        self.assertEqual(m["bytes"], 2326)
        self.assertEqual(m["referer"], "http://www.example.com/start.html")
        self.assertEqual(m["user_agent"], "Mozilla/4.08 [en] (Win98; I ;Nav)")
        self.assertEqual(m["request"], "GET /apache_pb.gif HTTP/1.0")

    def test_raw_strips_newline(self):
        self.assertEqual(self.ev.raw, COMBINED.rstrip("\n"))


class TestCommonAndEdgeCases(unittest.TestCase):
    def test_common_format(self):
        ev = parse_line(COMMON)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.src_ip, "198.51.100.4")
        self.assertIsNone(ev.user)
        self.assertEqual(ev.action, "POST")
        self.assertEqual(ev.status, "401")
        self.assertEqual(ev.meta["bytes"], 0)
        self.assertIsNone(ev.meta["referer"])
        self.assertIsNone(ev.meta["user_agent"])
        self.assertIsNone(ev.host)

    def test_dash_referer_and_agent_are_none(self):
        ev = parse_line('10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"')
        self.assertIsNone(ev.meta["referer"])
        self.assertIsNone(ev.meta["user_agent"])

    def test_ipv6_client(self):
        ev = parse_line('2001:db8::1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/2.0" 200 10 "-" "curl/8.0"')
        self.assertEqual(ev.src_ip, "2001:db8::1")
        self.assertEqual(ev.meta["user_agent"], "curl/8.0")

    def test_attack_path_kept_verbatim(self):
        ev = parse_line(
            '10.0.0.9 - - [01/Jan/2026:00:00:00 +0000] "GET /item?id=1%27%20OR%201=1--&q=<script> HTTP/1.1" '
            '403 0 "-" "sqlmap/1.7"'
        )
        self.assertEqual(ev.meta["path"], "/item?id=1%27%20OR%201=1--&q=<script>")
        self.assertEqual(ev.status, "403")
        self.assertEqual(ev.meta["user_agent"], "sqlmap/1.7")

    def test_non_http_request_line(self):
        # Scanners send TLS handshakes or junk to plain HTTP ports; nginx logs them as-is.
        ev = parse_line('10.0.0.9 - - [01/Jan/2026:00:00:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"')
        self.assertIsNotNone(ev)
        self.assertIsNone(ev.action)
        self.assertIsNone(ev.meta["path"])
        self.assertIsNone(ev.meta["protocol"])
        self.assertEqual(ev.meta["request"], "\\x16\\x03\\x01")
        self.assertEqual(ev.status, "400")

    def test_empty_request_line(self):
        ev = parse_line('10.0.0.9 - - [01/Jan/2026:00:00:00 +0000] "-" 408 0 "-" "-"')
        self.assertIsNotNone(ev)
        self.assertIsNone(ev.action)
        self.assertEqual(ev.status, "408")

    def test_malformed_returns_none(self):
        for bad in ["", "   \n", "not a log line", "10.0.0.1 - - [bad date] \"GET / HTTP/1.1\" 200 1",
                    '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" abc 1']:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_line(bad))


if __name__ == "__main__":
    unittest.main()
