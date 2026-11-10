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

CATEGORIES = ("path_traversal", "scanner", "sensitive_file", "sqli", "xss")


def classify(path: str | None, user_agent: str | None = None) -> list[str]:
    raise NotImplementedError("W3: implement HTTP signature classification")
