from datetime import datetime, timezone

from minisiem.parsers.auth import parse_journal, parse_line


def test_failed_password_invalid_user_rfc3339():
    ev = parse_line("2026-11-10T14:30:00.5+05:30 ari sshd-session[42]: "
                    "Failed password for invalid user admin from 198.51.100.23 port 52000 ssh2")
    assert ev.event_type == "auth_failure"
    assert (ev.user, ev.src_ip, ev.src_port, ev.host) == ("admin", "198.51.100.23", 52000, "ari")
    assert ev.meta["invalid_user"] is True
    assert ev.timestamp == datetime(2026, 11, 10, 9, 0, 0, 500000, tzinfo=timezone.utc)


def test_classic_syslog_accepted_and_invalid():
    ok = parse_line("Nov 10 09:00:00 ari sshd[7]: Accepted publickey for lakshya from 10.0.0.5 port 50000 ssh2",
                    year=2026)
    assert (ok.event_type, ok.status, ok.user, ok.meta["method"]) == ("auth_success", "success", "lakshya", "publickey")
    bad = parse_line("Nov  9 23:59:59 ari sshd[7]: Invalid user oracle from 2001:db8::7 port 22", year=2026)
    assert (bad.event_type, bad.user, bad.src_ip) == ("auth_invalid_user", "oracle", "2001:db8::7")


def test_sudo_lines():
    fail = parse_line("2026-11-10T09:00:00+00:00 ari sudo[1]: pam_unix(sudo:auth): authentication failure; "
                      "logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob")
    assert (fail.event_type, fail.user) == ("sudo_failure", "bob")
    cmd = parse_line("2026-11-10T09:00:00+00:00 ari sudo[1]: lakshya : TTY=pts/0 ; PWD=/home/lakshya ; "
                     "USER=root ; COMMAND=/usr/bin/apt update")
    assert (cmd.event_type, cmd.meta["command"], cmd.meta["target_user"]) == ("sudo_command", "/usr/bin/apt update", "root")
    denied = parse_line("2026-11-10T09:00:00+00:00 ari sudo[1]: eve : user NOT in sudoers ; TTY=pts/2 ; "
                        "PWD=/home/eve ; USER=root ; COMMAND=/bin/bash")
    assert (denied.event_type, denied.user) == ("sudo_failure", "eve")
    # the summary line repeats pam_unix failures, so it must not count again (or as a success)
    assert parse_line("2026-11-10T09:00:00+00:00 ari sudo[1]: bob : 3 incorrect password attempts ; TTY=pts/1 ; "
                      "PWD=/home/bob ; USER=root ; COMMAND=/bin/ls") is None


def test_untracked_and_junk_lines():
    assert parse_line("2026-11-10T09:00:00+00:00 ari CRON[5]: pam_unix(cron:session): session opened") is None
    assert parse_line("") is None
    assert parse_line("garbage") is None


def test_journal_entry():
    ev = parse_journal({"__REALTIME_TIMESTAMP": "1762765200000000", "_HOSTNAME": "ari",
                        "SYSLOG_IDENTIFIER": "sshd-session",
                        "MESSAGE": "Failed password for root from 203.0.113.50 port 41000 ssh2"})
    assert ev.event_type == "auth_failure" and ev.host == "ari" and ev.user == "root"
    assert ev.timestamp == datetime.fromtimestamp(1762765200, tz=timezone.utc)
    assert parse_journal({"__REALTIME_TIMESTAMP": "1", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": [1, 2]}) is None
    assert parse_journal({"MESSAGE": "x"}) is None
