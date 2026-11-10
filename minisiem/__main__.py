"""Run the Mini SIEM server: python -m minisiem [--host 0.0.0.0] [--port 8000]"""
import argparse
import os
import secrets

import uvicorn

from minisiem.api import create_app


def main() -> None:
    p = argparse.ArgumentParser(description="Mini SIEM server")
    p.add_argument("--host", default="127.0.0.1", help="bind address (use a Tailscale/LAN IP for remote agents)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--db", default="minisiem.db")
    p.add_argument("--rules", default=None, help="TOML file overriding rule thresholds")
    a = p.parse_args()
    key = os.environ.get("MINISIEM_API_KEY")
    if not key:
        key = secrets.token_urlsafe(24)
        print(f"MINISIEM_API_KEY not set; generated one for this run:\n  {key}\n")
    print(f"Dashboard: http://{a.host}:{a.port}/#key=<api key>")
    uvicorn.run(create_app(key, a.db, a.rules), host=a.host, port=a.port)


if __name__ == "__main__":
    main()
