import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detect import (
    WATCHLISTED_IPS,
    detect_brute_force,
    detect_credential_stuffing_success,
    detect_watchlisted_logins,
    run_all_detections,
)
from parse_logs import LoginEvent

ATTACK_IP = "203.0.113.77"
WATCHLIST_IP = next(iter(WATCHLISTED_IPS))


def make_event(event_type, username, ip, minute_offset=0, base=datetime(2026, 9, 10, 13, 0, 0)):
    return LoginEvent(
        timestamp=base + timedelta(minutes=minute_offset),
        event_type=event_type,
        username=username,
        source_ip=ip,
        port=51234,
        raw_line="synthetic-test-line",
    )


def test_detect_brute_force_flags_ip_over_threshold_in_window():
    events = [make_event("failed", "admin", ATTACK_IP, minute_offset=i) for i in range(6)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "brute_force"
    assert alerts[0].source_ip == ATTACK_IP
    assert alerts[0].severity == "medium"


def test_detect_brute_force_ignores_attempts_below_threshold():
    events = [make_event("failed", "admin", ATTACK_IP, minute_offset=i) for i in range(4)]
    alerts = detect_brute_force(events)
    assert alerts == []


def test_detect_brute_force_ignores_attempts_spread_outside_window():
    # 6 failed attempts but 20 minutes apart each -> never >= threshold inside a 10 min window
    events = [make_event("failed", "admin", ATTACK_IP, minute_offset=i * 20) for i in range(6)]
    alerts = detect_brute_force(events)
    assert alerts == []


def test_detect_credential_stuffing_success_requires_prior_brute_force_ip():
    brute_force_ips = {ATTACK_IP}
    events = [
        make_event("accepted", "jsmith", ATTACK_IP, minute_offset=15),
        make_event("accepted", "normaluser", "10.0.0.14", minute_offset=16),
    ]
    alerts = detect_credential_stuffing_success(events, brute_force_ips)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert alerts[0].source_ip == ATTACK_IP
    assert alerts[0].username == "jsmith"


def test_detect_watchlisted_logins_flags_only_watchlisted_ip():
    events = [
        make_event("accepted", "jdoe", WATCHLIST_IP, minute_offset=1),
        make_event("accepted", "normaluser", "10.0.0.14", minute_offset=2),
    ]
    alerts = detect_watchlisted_logins(events)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "watchlisted_source"
    assert alerts[0].source_ip == WATCHLIST_IP


def test_run_all_detections_orders_high_severity_first():
    events = [make_event("failed", "admin", ATTACK_IP, minute_offset=i) for i in range(6)]
    events.append(make_event("accepted", "admin", ATTACK_IP, minute_offset=7))
    events.append(make_event("accepted", "jdoe", WATCHLIST_IP, minute_offset=8))

    alerts = run_all_detections(events)
    assert len(alerts) == 3
    assert alerts[0].severity == "high"
    assert alerts[0].alert_type == "credential_stuffing_success"
    assert {a.severity for a in alerts[1:]} == {"medium"}
