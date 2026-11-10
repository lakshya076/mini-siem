"""Wait until the server holds alerts for every expected rule; exit 1 if they do not appear in time.

  MINISIEM_API_KEY=... python tools/e2e_check.py --server http://127.0.0.1:8000 \
      --expect brute_force,port_scan,suspicious_http --wait 120 [--ip 100.64.0.1]
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request


def fetch_alerts(server: str, key: str, ip: str | None) -> list[dict]:
    qs = urllib.parse.urlencode({"limit": 1000, **({"ip": ip} if ip else {})})
    req = urllib.request.Request(f"{server.rstrip('/')}/api/alerts?{qs}", headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--server", default="http://127.0.0.1:8000")
    p.add_argument("--expect", required=True, help="comma-separated rule ids")
    p.add_argument("--ip", help="only count alerts from this source IP")
    p.add_argument("--wait", type=float, default=60, help="seconds to keep polling")
    a = p.parse_args()
    key = os.environ.get("MINISIEM_API_KEY") or sys.exit("set MINISIEM_API_KEY")
    expected = {r.strip() for r in a.expect.split(",") if r.strip()}
    deadline = time.monotonic() + a.wait
    while True:
        alerts = fetch_alerts(a.server, key, a.ip)
        seen = {x["rule"] for x in alerts}
        missing = expected - seen
        if not missing or time.monotonic() > deadline:
            break
        time.sleep(3)
    for x in sorted(alerts, key=lambda x: x["timestamp"]):
        print(f"{x['timestamp'][:19]}  {x['severity']:8}  {x['rule']:24} {x['src_ip'] or '-':16} {x['description'][:70]}")
    for rule in sorted(expected):
        print(f"{'PASS' if rule in seen else 'FAIL'}  {rule}")
    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
