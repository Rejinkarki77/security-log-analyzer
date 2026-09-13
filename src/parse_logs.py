"""
Parses SSH auth log lines into structured login events. Written against
the standard OpenSSH log format so it works on real /var/log/auth.log
(or /var/log/secure on RHEL-based systems) with no changes.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)


@dataclass
class LoginEvent:
    timestamp: datetime
    event_type: str  # "failed" or "accepted"
    username: str
    source_ip: str
    port: int
    raw_line: str


def _parse_ts(ts_str: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int = 2026) -> Optional[LoginEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = FAILED_RE.match(line)
    if m:
        return LoginEvent(
            timestamp=_parse_ts(m.group("ts"), year),
            event_type="failed",
            username=m.group("user"),
            source_ip=m.group("ip"),
            port=int(m.group("port")),
            raw_line=line,
        )

    m = ACCEPTED_RE.match(line)
    if m:
        return LoginEvent(
            timestamp=_parse_ts(m.group("ts"), year),
            event_type="accepted",
            username=m.group("user"),
            source_ip=m.group("ip"),
            port=int(m.group("port")),
            raw_line=line,
        )

    return None


def parse_log_file(path: Path, year: int = 2026) -> List[LoginEvent]:
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line, year=year)
            if event:
                events.append(event)
    return events
