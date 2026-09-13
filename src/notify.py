"""
Optional: posts a Microsoft Teams alert via an Incoming Webhook when a
high-severity alert (credential stuffing success) is detected.

Honesty note: same as the invoice project — this is written against
Teams' documented webhook format but untested against a real tenant,
since I don't have one to test against. Ready to connect, not yet
proven in production.
"""

import json
import os
import urllib.request

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")


def send_teams_alert(summary: str, alerts: list) -> bool:
    if not TEAMS_WEBHOOK_URL:
        print("[notify] TEAMS_WEBHOOK_URL not set — skipping Teams alert (see notify.py docstring).")
        return False

    facts = [
        {"name": a.alert_type, "value": f"{a.source_ip} — {a.reason}"}
        for a in alerts
    ]
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": summary,
        "themeColor": "D9534F",
        "title": "Security Log Analyzer — high-severity alert",
        "text": summary,
        "sections": [{"facts": facts}] if facts else [],
    }

    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"[notify] Teams alert failed: {e}")
        return False
