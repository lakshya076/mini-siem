"""Mini SIEM collection agent.

Standard library only, imports nothing from minisiem, so this one file can be copied to any monitored host.
It tails log files and/or journald and ships raw records to the server, which parses them.

  python3 agent.py --server http://100.x.y.z:8000 --journal --file web:/var/log/nginx/access.log
  (API key from MINISIEM_API_KEY)
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

KINDS = ("auth", "web", "firewall")
JOURNAL_FIELDS = ("__REALTIME_TIMESTAMP", "MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_HOSTNAME", "_TRANSPORT")
# (sshd OR sshd-session OR sudo) OR kernel; journalctl ORs same-field matches and "+"-separated groups
JOURNAL_CMD = ["journalctl", "-f", "-o", "json", "-n", "0", "SYSLOG_IDENTIFIER=sshd",
               "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo", "+", "_TRANSPORT=kernel"]
MAX_BUFFER = 20_000


def log(msg: str) -> None:
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


def tail_file(kind: str, path: str, out: queue.Queue, from_start: bool, poll: float = 0.5) -> None:
    """Follow a file like `tail -F`: survives rotation (new inode) and truncation."""
    f, inode, buf = None, None, ""
    while True:
        if f is None:
            try:
                f = open(path, encoding="utf-8", errors="replace", newline="")
                inode = os.fstat(f.fileno()).st_ino
                if not from_start:
                    f.seek(0, os.SEEK_END)
                from_start = True  # a rotated-in file is read from its start
                log(f"tailing {kind}:{path}")
            except OSError as exc:
                log(f"cannot open {path}: {exc}; retrying")
                time.sleep(5)
                continue
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                out.put({"kind": kind, "line": buf.rstrip("\r\n")})
                buf = ""
            continue
        time.sleep(poll)
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = None
        except OSError:
            pass  # file briefly missing during rotation


def follow_journal(out: queue.Queue) -> None:
    while True:
        try:
            proc = subprocess.Popen(JOURNAL_CMD, stdout=subprocess.PIPE, text=True, encoding="utf-8",
                                    errors="replace")
        except OSError as exc:
            log(f"cannot start journalctl: {exc}")
            return
        log("following journald (sshd, sudo, kernel)")
        for line in proc.stdout:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            out.put({"kind": "journal", "entry": {k: entry[k] for k in JOURNAL_FIELDS if k in entry}})
        log(f"journalctl exited ({proc.wait()}); restarting in 5s")
        time.sleep(5)


def post(server: str, key: str, host: str, records: list) -> dict:
    body = json.dumps({"host": host, "records": records}).encode()
    req = urllib.request.Request(f"{server.rstrip('/')}/api/ingest", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def ship(server: str, key: str, host: str, q: queue.Queue, batch: int = 500, interval: float = 2.0) -> None:
    pending: list = []
    backoff = 1.0
    while True:
        deadline = time.monotonic() + interval
        while len(pending) < batch and (left := deadline - time.monotonic()) > 0:
            try:
                pending.append(q.get(timeout=left))
            except queue.Empty:
                break
        if not pending:
            continue
        try:
            res = post(server, key, host, pending[:batch])
            log(f"sent {min(len(pending), batch)}: {res}")
            del pending[:batch]
            backoff = 1.0
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 422):
                log(f"server rejected batch: HTTP {exc.code} {exc.read()[:200]!r}; dropping it")
                del pending[:batch]
            else:
                log(f"server error HTTP {exc.code}; retrying in {backoff:.0f}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
        except (urllib.error.URLError, OSError) as exc:
            log(f"server unreachable ({exc}); retrying in {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        if len(pending) > MAX_BUFFER:
            log(f"buffer full, dropping {len(pending) - MAX_BUFFER} oldest records")
            del pending[:len(pending) - MAX_BUFFER]


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Mini SIEM log collection agent")
    p.add_argument("--server", required=True, help="e.g. http://100.64.0.1:8000")
    p.add_argument("--file", action="append", default=[], metavar="KIND:PATH",
                   help=f"log file to tail, KIND one of {', '.join(KINDS)} (repeatable)")
    p.add_argument("--journal", action="store_true", help="follow journald for sshd, sudo and kernel firewall logs")
    p.add_argument("--from-start", action="store_true", help="read files from the beginning instead of the end")
    p.add_argument("--host", default=socket.gethostname(), help="host name reported for these logs")
    a = p.parse_args(argv)

    key = os.environ.get("MINISIEM_API_KEY")
    if not key:
        p.error("set MINISIEM_API_KEY")
    if not a.file and not a.journal:
        p.error("give at least one --file or --journal")
    q: queue.Queue = queue.Queue()
    for spec in a.file:
        kind, sep, path = spec.partition(":")
        if not sep or kind not in KINDS:
            p.error(f"bad --file {spec!r}; expected KIND:PATH with KIND in {KINDS}")
        threading.Thread(target=tail_file, args=(kind, path, q, a.from_start), daemon=True).start()
    if a.journal:
        threading.Thread(target=follow_journal, args=(q,), daemon=True).start()
    try:
        ship(a.server, key, a.host, q)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
