"""Acceptance tests for task W2 (minisiem/parsers/firewall.py). Stdlib unittest only.

Run: python3 -m unittest tests.test_firewall_parser -v
"""
import unittest
from datetime import datetime, timezone

from minisiem.parsers.firewall import parse_line

BODY = (
    "IN=enp1s0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=100.64.1.2 DST=100.101.58.76 "
    "LEN=44 TOS=0x00 PREC=0x00 TTL=42 ID=31337 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0"
)
CLASSIC = f"Nov 10 12:34:56 ari kernel: [12345.678901] [UFW BLOCK] {BODY}\n"
RFC3339 = f"2026-11-10T12:34:56.000000+05:30 ari kernel: [UFW ALLOW] {BODY}"
BARE = f"[UFW BLOCK] {BODY}"


class TestClassicSyslog(unittest.TestCase):
    def setUp(self):
        self.ev = parse_line(CLASSIC, year=2026)

    def test_core_fields(self):
        ev = self.ev
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source, "firewall")
        self.assertEqual(ev.action, "block")
        self.assertEqual(ev.event_type, "firewall_block")
        self.assertEqual(ev.severity, "info")
        self.assertEqual(ev.src_ip, "100.64.1.2")
        self.assertEqual(ev.dst_ip, "100.101.58.76")
        self.assertEqual(ev.src_port, 54321)
        self.assertEqual(ev.dst_port, 22)
        self.assertEqual(ev.host, "ari")
        self.assertEqual(ev.raw, CLASSIC.rstrip("\n"))

    def test_timestamp(self):
        self.assertEqual(self.ev.timestamp, datetime(2026, 11, 10, 12, 34, 56, tzinfo=timezone.utc))

    def test_meta(self):
        m = self.ev.meta
        self.assertEqual(m["proto"], "TCP")
        self.assertEqual(m["in"], "enp1s0")
        self.assertIsNone(m["out"])
        self.assertEqual(m["flags"], ["SYN"])  # URGP=0 must not count as URG


class TestOtherShapes(unittest.TestCase):
    def test_rfc3339_converted_to_utc(self):
        ev = parse_line(RFC3339)
        self.assertEqual(ev.timestamp, datetime(2026, 11, 10, 7, 4, 56, tzinfo=timezone.utc))
        self.assertEqual(ev.action, "allow")
        self.assertEqual(ev.event_type, "firewall_allow")
        self.assertEqual(ev.host, "ari")

    def test_bare_message_uses_default_time_and_host_arg(self):
        t = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        ev = parse_line(BARE, host="ari", default_time=t)
        self.assertEqual(ev.timestamp, t)
        self.assertEqual(ev.host, "ari")
        self.assertEqual(ev.dst_port, 22)

    def test_bare_message_without_default_time_is_recent_utc(self):
        ev = parse_line(BARE)
        self.assertIsNotNone(ev.timestamp.tzinfo)
        self.assertLess(abs((datetime.now(timezone.utc) - ev.timestamp).total_seconds()), 60)

    def test_action_mapping(self):
        cases = {
            "[UFW LIMIT BLOCK]": "block",
            "[UFW AUDIT]": "audit",
            "IPTABLES-DROP: ": "block",
            "iptables reject: ": "block",
            "FW-ACCEPT ": "allow",
            "SOMETHING ": "log",
        }
        for prefix, action in cases.items():
            with self.subTest(prefix=prefix):
                ev = parse_line(f"{prefix}{BODY}")
                self.assertEqual(ev.action, action)
                self.assertEqual(ev.event_type, f"firewall_{action}")

    def test_icmp_has_no_ports(self):
        ev = parse_line(
            "[UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.1 LEN=84 TTL=64 ID=1 PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1"
        )
        self.assertEqual(ev.meta["proto"], "ICMP")
        self.assertIsNone(ev.src_port)
        self.assertIsNone(ev.dst_port)
        self.assertEqual(ev.meta["flags"], [])

    def test_multiple_flags_in_order(self):
        ev = parse_line(f"[UFW BLOCK] IN=eth0 OUT= SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP SPT=1 DPT=2 ACK PSH FIN URGP=0")
        self.assertEqual(ev.meta["flags"], ["ACK", "PSH", "FIN"])

    def test_outbound_iface(self):
        ev = parse_line("[UFW BLOCK] IN= OUT=wg0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP SPT=53 DPT=5353")
        self.assertIsNone(ev.meta["in"])
        self.assertEqual(ev.meta["out"], "wg0")
        self.assertEqual(ev.meta["proto"], "UDP")

    def test_non_firewall_returns_none(self):
        for bad in ["", "\n", "Nov 10 12:34:56 ari sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
                    "random text"]:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_line(bad))


if __name__ == "__main__":
    unittest.main()
