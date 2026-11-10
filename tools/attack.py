"""Attack simulator for testing Mini SIEM in a lab. Only run it against machines you own or may test.

  python tools/attack.py --target 100.101.58.76 --scan            # TCP connect scan of ports 1-1024
  python tools/attack.py --target 100.101.58.76 --ssh 8           # failed SSH password logins (needs paramiko)
  python tools/attack.py --target 100.101.58.76 --http 8080       # malicious HTTP requests to tools/demo_web.py
"""
import argparse
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HTTP_ATTACKS = [
    ("/products?id=1%27%20OR%201=1--", "curl/8.5.0"),
    ("/download?file=../../../../etc/passwd", "curl/8.5.0"),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "curl/8.5.0"),
    ("/.env", "curl/8.5.0"),
    ("/.git/config", "curl/8.5.0"),
] + [(f"/dir-{i}", "gobuster/3.6") for i in range(25)]   # content discovery: 404 flood + scanner UA


def scan(target: str, ports=range(1, 1025)) -> None:
    def probe(port):
        with socket.socket() as s:
            s.settimeout(0.5)
            return port if s.connect_ex((target, port)) == 0 else None
    with ThreadPoolExecutor(64) as pool:
        open_ports = [p for p in pool.map(probe, ports) if p]
    print(f"scan done: {len(ports)} ports probed, open: {open_ports}")


def ssh(target: str, attempts: int, users: list[str]) -> None:
    try:
        import paramiko
    except ImportError:
        sys.exit("--ssh needs paramiko: pip install paramiko")
    for i in range(attempts):
        user = users[i % len(users)]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # lab target, host key not checked
        try:
            client.connect(target, username=user, password=f"wrong-password-{i}", timeout=10,
                           allow_agent=False, look_for_keys=False)
            print(f"{user}: unexpectedly logged in!")
        except paramiko.AuthenticationException:
            print(f"{user}: authentication failed (expected)")
        except Exception as exc:  # banner/timeout errors still count as attempts on the target side
            print(f"{user}: {type(exc).__name__}: {exc}")
        finally:
            client.close()


def http(target: str, port: int) -> None:
    for path, ua in HTTP_ATTACKS:
        req = urllib.request.Request(f"http://{target}:{port}{path}", headers={"User-Agent": ua})
        try:
            code = urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as exc:
            code = exc.code
        print(f"{code} {path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--target", required=True)
    p.add_argument("--scan", action="store_true")
    p.add_argument("--ssh", type=int, metavar="N", help="number of failed SSH logins")
    p.add_argument("--ssh-users", default="root,admin,test,oracle,postgres,guest")
    p.add_argument("--http", type=int, metavar="PORT", help="port of tools/demo_web.py on the target")
    a = p.parse_args()
    if not (a.scan or a.ssh or a.http):
        p.error("choose at least one of --scan, --ssh, --http")
    if a.scan:
        scan(a.target)
    if a.ssh:
        ssh(a.target, a.ssh, a.ssh_users.split(","))
    if a.http:
        http(a.target, a.http)


if __name__ == "__main__":
    main()
