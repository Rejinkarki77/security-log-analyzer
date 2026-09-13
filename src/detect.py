"""
Detection rules over parsed login events. Explainable, threshold-based
rules on purpose — the same reasoning as the invoice project's validator:
a human triaging alerts needs to see exactly why something fired, not
trust a black box. A learned/statistical anomaly model is a natural v2
extension once there's real historical traffic to baseline against.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

# Tunable thresholds — in a real deployment these would come from config,
# not be hardcoded, and would likely differ per environment.
BRUTE_FORCE_FAILED_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10

# Simulates a threat-intel feed of known-bad / unusual source ranges.
# In production this would be pulled from a real feed (AbuseIPDB, internal
# blocklist, etc.) rather than hardcoded.
WATCHLISTED_IPS = {"198.51.100.23"}


@dataclass
class Alert:
    severity: str  # "high", "medium", "low"
    alert_type: str
    source_ip: str
    username: str
    timestamp: object
    reason: str


def detect_brute_force(events: List) -> List[Alert]:
    """Flags any IP with >= threshold failed logins inside the time window."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "failed":
            by_ip[e.source_ip].append(e)

    for ip, fails in by_ip.items():
        fails = sorted(fails, key=lambda e: e.timestamp)
        # sliding window check
        for i in range(len(fails)):
            window_end = fails[i].timestamp + timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
            count_in_window = sum(1 for f in fails[i:] if f.timestamp <= window_end)
            if count_in_window >= BRUTE_FORCE_FAILED_THRESHOLD:
                alerts.append(
                    Alert(
                        severity="medium",
                        alert_type="brute_force",
                        source_ip=ip,
                        username="(multiple)",
                        timestamp=fails[i].timestamp,
                        reason=f"{count_in_window} failed logins from {ip} within {BRUTE_FORCE_WINDOW_MINUTES} minutes",
                    )
                )
                break  # one alert per IP is enough for this demo
    return alerts


def detect_credential_stuffing_success(events: List, brute_force_ips: set) -> List[Alert]:
    """
    The highest-severity signal: a successful login from an IP that was
    already flagged for brute-forcing. This usually means the attacker
    got in.
    """
    alerts = []
    for e in events:
        if e.event_type == "accepted" and e.source_ip in brute_force_ips:
            alerts.append(
                Alert(
                    severity="high",
                    alert_type="credential_stuffing_success",
                    source_ip=e.source_ip,
                    username=e.username,
                    timestamp=e.timestamp,
                    reason=f"Successful login for '{e.username}' from {e.source_ip} after that IP was flagged for brute-forcing",
                )
            )
    return alerts


def detect_watchlisted_logins(events: List) -> List[Alert]:
    """Flags any successful login from a watchlisted source IP."""
    alerts = []
    for e in events:
        if e.event_type == "accepted" and e.source_ip in WATCHLISTED_IPS:
            alerts.append(
                Alert(
                    severity="medium",
                    alert_type="watchlisted_source",
                    source_ip=e.source_ip,
                    username=e.username,
                    timestamp=e.timestamp,
                    reason=f"Successful login for '{e.username}' from watchlisted IP {e.source_ip}",
                )
            )
    return alerts


def run_all_detections(events: List) -> List[Alert]:
    brute_force_alerts = detect_brute_force(events)
    brute_force_ips = {a.source_ip for a in brute_force_alerts}

    all_alerts = []
    all_alerts.extend(brute_force_alerts)
    all_alerts.extend(detect_credential_stuffing_success(events, brute_force_ips))
    all_alerts.extend(detect_watchlisted_logins(events))

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    all_alerts.sort(key=lambda a: (severity_rank.get(a.severity, 9), a.timestamp))
    return all_alerts
