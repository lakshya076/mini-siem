from datetime import datetime, timedelta, timezone

import pytest

from minisiem.detection import Detector, load_config
from minisiem.event import Event

T0 = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)


def ev(sec, event_type, source="auth", **kw):
    return Event(timestamp=T0 + timedelta(seconds=sec), source=source, event_type=event_type,
                 raw=f"{event_type}@{sec}", **kw)


def run(events, config=None):
    d = Detector(config)
    return [a for e in events for a in d.process(e)]


def rules(alerts):
    return [a.rule for a in alerts]


def test_brute_force_threshold_and_window():
    fails = [ev(i * 10, "auth_failure", src_ip="1.2.3.4", user="alice") for i in range(5)]
    alerts = run(fails)
    assert rules(alerts) == ["brute_force"]
    assert alerts[0].severity == "high" and alerts[0].mitre == "T1110.001" and len(alerts[0].evidence) == 5
    # same count spread over more than 60 s does not alert
    assert rules(run([ev(i * 20, "auth_failure", src_ip="1.2.3.4", user="alice") for i in range(5)])) == []


def test_alert_suppression_per_key():
    fails = [ev(i, "auth_failure", src_ip="1.2.3.4", user="alice") for i in range(20)]
    assert rules(run(fails)) == ["brute_force"]          # suppressed for 300 s after the first alert
    later = fails + [ev(400 + i, "auth_failure", src_ip="1.2.3.4", user="alice") for i in range(5)]
    assert rules(run(later)) == ["brute_force", "brute_force"]
    other_ip = fails + [ev(30 + i, "auth_failure", src_ip="5.6.7.8", user="alice") for i in range(5)]
    assert rules(run(other_ip)).count("brute_force") == 2


def test_password_spray_counts_distinct_users():
    evs = [ev(i * 30, "auth_invalid_user", src_ip="9.9.9.9", user=u) for i, u in enumerate("abcde")]
    alerts = [a for a in run(evs) if a.rule == "password_spray"]
    assert len(alerts) == 1 and "5 different usernames" in alerts[0].description
    same_user = [ev(i * 30, "auth_invalid_user", src_ip="9.9.9.9", user="a") for i in range(6)]
    assert "password_spray" not in rules(run(same_user))


def test_success_after_failures_is_critical():
    evs = [ev(i * 30, "auth_failure", src_ip="7.7.7.7", user="bob") for i in range(3)]
    alerts = run(evs + [ev(100, "auth_success", src_ip="7.7.7.7", user="bob")])
    assert rules(alerts) == ["success_after_failures"]
    assert alerts[0].severity == "critical" and alerts[0].user == "bob"
    # a clean login is fine, and so is one long after the failures
    assert rules(run([ev(0, "auth_success", src_ip="7.7.7.7", user="bob")])) == []
    assert rules(run(evs + [ev(5000, "auth_success", src_ip="7.7.7.7", user="bob")])) == []


def test_invalid_and_root_login_attempts():
    alerts = run([ev(0, "auth_invalid_user", src_ip="1.1.1.1", user="oracle"),
                  ev(1, "auth_failure", src_ip="1.1.1.1", user="root"),
                  ev(2, "auth_failure", src_ip="1.1.1.1", user="alice")])
    assert rules(alerts) == ["invalid_user", "invalid_user"]
    assert all(a.severity == "medium" for a in alerts)


def test_port_scan_distinct_ports_only_blocked():
    scan = [ev(i, "firewall_block", source="firewall", action="block", src_ip="6.6.6.6", dst_port=p)
            for i, p in enumerate(range(20, 30))]
    alerts = run(scan)
    assert rules(alerts) == ["port_scan"] and alerts[0].mitre == "T1046"
    same_port = [ev(i, "firewall_block", source="firewall", action="block", src_ip="6.6.6.6", dst_port=22)
                 for i in range(30)]
    assert rules(run(same_port)) == []
    allowed = [ev(i, "firewall_allow", source="firewall", action="allow", src_ip="6.6.6.6", dst_port=p)
               for i, p in enumerate(range(20, 40))]
    assert rules(run(allowed)) == []


def web(sec, path, status="200", ua="Mozilla/5.0", ip="4.4.4.4"):
    return ev(sec, "http_request", source="web", src_ip=ip, status=status,
              meta={"path": path, "user_agent": ua, "request": f"GET {path} HTTP/1.1"})


def test_suspicious_http_severity():
    alerts = run([web(0, "/item?id=1' or 1=1--"), web(1, "/.env"), web(2, "/")])
    assert [(a.rule, a.severity) for a in alerts] == [("suspicious_http", "high"), ("suspicious_http", "medium")]


def test_http_error_flood():
    alerts = run([web(i, f"/page{i}", status="404") for i in range(20)])
    assert rules(alerts) == ["http_error_flood"]
    assert rules(run([web(i, f"/page{i}", status="200") for i in range(50)])) == []


def test_sudo_failures_per_user_and_host():
    evs = [ev(i * 10, "sudo_failure", user="bob", host="ari") for i in range(3)]
    assert rules(run(evs)) == ["sudo_failures"]
    mixed = [ev(0, "sudo_failure", user="bob", host="ari"), ev(1, "sudo_failure", user="eve", host="ari"),
             ev(2, "sudo_failure", user="bob", host="other")]
    assert rules(run(mixed)) == []


def test_config_override(tmp_path):
    f = tmp_path / "rules.toml"
    f.write_text("[brute_force]\nthreshold = 2\n")
    cfg = load_config(f)
    assert cfg["brute_force"] == {"window": 60, "threshold": 2}
    assert rules(run([ev(i, "auth_failure", src_ip="1.2.3.4", user="x") for i in range(2)], cfg)) == ["brute_force"]
    f.write_text("[no_such_rule]\nthreshold = 1\n")
    with pytest.raises(ValueError):
        load_config(f)
