"""Replay sample logs into a Mini SIEM server (single-machine demo, also used by the tests).

  MINISIEM_API_KEY=... python tools/replay.py --server http://127.0.0.1:8000 [--dir samples]
"""
import argparse
import os
import sys
from pathlib import Path

from minisiem.agent import post

KIND_BY_FILE = {"auth.log": "auth", "access.log": "web", "ufw.log": "firewall"}
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load_samples(directory: Path = SAMPLES) -> list[dict]:
    records = []
    for name, kind in KIND_BY_FILE.items():
        path = directory / name
        if path.exists():
            records += [{"kind": kind, "line": line} for line in path.read_text(encoding="utf-8").splitlines() if line]
    return records


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--server", default="http://127.0.0.1:8000")
    p.add_argument("--dir", type=Path, default=SAMPLES)
    p.add_argument("--host", default="ari", help="host name reported for the replayed logs")
    a = p.parse_args()
    key = os.environ.get("MINISIEM_API_KEY") or sys.exit("set MINISIEM_API_KEY")
    records = load_samples(a.dir)
    print(post(a.server, key, a.host, records))


if __name__ == "__main__":
    main()
