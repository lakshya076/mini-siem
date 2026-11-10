"""Acceptance tests for task W3 (minisiem/detection/http_signatures.py). Stdlib unittest only.

Run: python3 -m unittest tests.test_http_signatures -v
"""
import unittest

from minisiem.detection.http_signatures import classify


class TestCategories(unittest.TestCase):
    def check(self, path, ua, expected):
        with self.subTest(path=path, ua=ua):
            self.assertEqual(classify(path, ua), expected)

    def test_sqli(self):
        self.check("/item?id=1%27%20OR%201=1--", None, ["sqli"])
        self.check("/search?q=x UNION SELECT username,password FROM users", None, ["sqli"])
        self.check("/p?id=1+union+all+select+null", None, ["sqli"])
        self.check("/p?id=1 AND SLEEP(5)", None, ["sqli"])
        self.check("/p?t=information_schema.tables", None, ["sqli"])

    def test_xss(self):
        self.check("/q?s=<script>alert(1)</script>", None, ["xss"])
        self.check("/q?s=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", None, ["xss"])
        self.check("/r?next=javascript:void(0)", None, ["xss"])

    def test_path_traversal(self):
        self.check("/download?file=../../../../etc/passwd", None, ["path_traversal"])
        self.check("/static/%2e%2e%2f%2e%2e%2fetc%2fshadow", None, ["path_traversal"])
        self.check("/x/..%252f..%252fwin.ini", None, ["path_traversal"])  # double-encoded
        self.check("/f?p=..\\..\\boot.ini", None, ["path_traversal"])

    def test_sensitive_file(self):
        for p in ["/.env", "/.git/config", "/wp-login.php", "/WP-ADMIN/", "/phpMyAdmin/index.php",
                  "/.aws/credentials", "/server-status"]:
            self.check(p, None, ["sensitive_file"])

    def test_scanner_user_agent(self):
        for ua in ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0)",
                   "Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project", "gobuster/3.6"]:
            self.check("/", ua, ["scanner"])

    def test_multiple_categories_sorted_unique(self):
        self.check("/.git/../../etc/passwd?q=<script>", "sqlmap/1.7",
                   ["path_traversal", "scanner", "sensitive_file", "xss"])
        self.check("/a?x=' or 1=1--&y=' or 2=2", None, ["sqli"])


class TestBenign(unittest.TestCase):
    def test_benign_requests(self):
        cases = [
            ("/", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"),
            ("/scripts/app.js", "Mozilla/5.0"),
            ("/union-station/selection?order=asc", "curl/8.5.0"),
            ("/javascript-guide.html", None),
            ("/environment/settings", None),
            ("/docs/v1.2/report..final.pdf", None),
            ("/github/readme", None),
            ("/search?q=select+a+plan", None),
            ("/api/orders?sort=desc&page=2", "python-requests/2.32"),
        ]
        for path, ua in cases:
            with self.subTest(path=path, ua=ua):
                self.assertEqual(classify(path, ua), [])

    def test_none_and_junk_inputs(self):
        self.assertEqual(classify(None, None), [])
        self.assertEqual(classify("", ""), [])
        self.assertEqual(classify("%%%zz%", None), [])
        self.assertEqual(classify("\\x16\\x03\\x01", None), [])


if __name__ == "__main__":
    unittest.main()
