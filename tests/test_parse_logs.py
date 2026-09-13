import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from parse_logs import parse_line


def test_parses_failed_invalid_user():
    line = "Sep 10 13:12:06 prod-web-01 sshd[18422]: Failed password for invalid user admin from 203.0.113.77 port 51234 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed"
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.77"
    assert event.port == 51234


def test_parses_accepted_login():
    line = "Sep 10 08:14:02 prod-web-01 sshd[18422]: Accepted password for jsmith from 10.0.0.14 port 52011 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "accepted"
    assert event.username == "jsmith"
    assert event.source_ip == "10.0.0.14"


def test_ignores_unrelated_lines():
    assert parse_line("Sep 10 08:14:02 prod-web-01 systemd[1]: Started session.") is None
    assert parse_line("") is None


def test_timestamp_parsed_correctly():
    line = "Sep 10 13:12:06 prod-web-01 sshd[18422]: Failed password for invalid user root from 203.0.113.77 port 40000 ssh2"
    event = parse_line(line, year=2026)
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 10
    assert event.timestamp.hour == 13
    assert event.timestamp.minute == 12
