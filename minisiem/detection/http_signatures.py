"""Signature matching for suspicious HTTP requests.

TASK W3 (HiveMind worker): implement classify(). Standard library only (re, urllib.parse).
Spec (tests/test_http_signatures.py is the source of truth):

classify(path, user_agent) returns a sorted list of unique category names that match, or [] when
nothing matches. Either argument may be None (treat None as "").

Before matching `path`: URL-decode it with urllib.parse.unquote_plus up to 3 times (stop early when
it no longer changes), then lowercase it. Match `user_agent` lowercased.

Categories (match on the decoded, lowercased path unless noted):
  "sqli"            any of: "union select", "union all select", "' or ", "\" or ", "or 1=1",
                    "information_schema", "sleep(", "benchmark(", "; drop ", "'--", "' --", "' #"
  "xss"             any of: "<script", "javascript:", "onerror=", "onload=", "alert(", "<svg", "<iframe"
  "path_traversal"  any of: "../", "..\\", "/etc/passwd", "/etc/shadow", "c:\\windows", "/proc/self/"
  "sensitive_file"  path contains any of: "/.env", "/.git/", "/.aws/", "/wp-login.php", "/wp-admin",
                    "/phpmyadmin", "/server-status", "/.ds_store"
  "scanner"         user_agent contains any of: "sqlmap", "nikto", "nmap", "masscan", "zgrab",
                    "gobuster", "dirbuster", "wpscan", "nuclei", "acunetix", "hydra"

Never raise on any input.
"""
from __future__ import annotations

import urllib.parse

CATEGORIES = ("path_traversal", "scanner", "sensitive_file", "sqli", "xss")

# Substring lists extracted from docstring, matching exact category keywords
_SQli_SUBSTRINGS = [
    "union select", "union all select", "' or ", '" or ', "or 1=1",
    "information_schema", "sleep(", "benchmark(", "; drop ",
    "'--", "' --", "' #",
]
_XSS_SUBSTRINGS = ["<script", "javascript:", "onerror=", "onload=", "alert(", "<svg", "<iframe"]
_PATH_TRAVERSAL_SUBSTRINGS = ["../", "..\\", "/etc/passwd", "/etc/shadow", "c:\\windows", "/proc/self/"]
_SENSITIVE_FILE_SUBSTRINGS = ["/.env", "/.git/", "/.aws/", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/server-status", "/.ds_store"]
_SCANNER_SUBSTRINGS = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "wpscan", "nuclei", "acunetix", "hydra"]


def classify(path: str | None, user_agent: str | None = None) -> list[str]:
    # Decode path: up to 3 times with unquote_plus, stop early if no change
    p = path if path is not None else ""
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(p)
        if decoded == p:
            break
        p = decoded
    p = p.lower()

    # Lowercase user agent
    ua = (user_agent if user_agent is not None else "").lower()

    result = []
    seen = set()

    # Check categories in CATEGORIES order to preserve the expected sort order
    for cat in CATEGORIES:
        if cat == "path_traversal":
            if any(sub in p for sub in _PATH_TRAVERSAL_SUBSTRINGS) and "path_traversal" not in seen:
                result.append("path_traversal")
                seen.add("path_traversal")
        elif cat == "scanner":
            if any(sub in ua for sub in _SCANNER_SUBSTRINGS) and "scanner" not in seen:
                result.append("scanner")
                seen.add("scanner")
        elif cat == "sensitive_file":
            if any(sub in p for sub in _SENSITIVE_FILE_SUBSTRINGS) and "sensitive_file" not in seen:
                result.append("sensitive_file")
                seen.add("sensitive_file")
        elif cat == "sqli":
            if any(sub in p for sub in _SQli_SUBSTRINGS) and "sqli" not in seen:
                result.append("sqli")
                seen.add("sqli")
        elif cat == "xss":
            if any(sub in p for sub in _XSS_SUBSTRINGS) and "xss" not in seen:
                result.append("xss")
                seen.add("xss")

    return result
