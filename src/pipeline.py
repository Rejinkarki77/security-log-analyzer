"""
End-to-end pipeline: parse the auth log -> run detection rules -> store
events + alerts in SQLite -> rebuild the analyst dashboard -> alert Teams
on any high-severity finding.

Run: python src/pipeline.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import dashboard
import db
from detect import run_all_detections
from notify import send_teams_alert
from parse_logs import parse_log_file

LOG_PATH = Path(__file__).parent.parent / "data" / "logs" / "auth.log"


def run():
    print(f"Parsing {LOG_PATH}...")
    events = parse_log_file(LOG_PATH)
    print(f"Parsed {len(events)} login events.")

    alerts = run_all_detections(events)
    print(f"Detected {len(alerts)} alert(s).")

    conn = db.reset_db()
    db.insert_events(conn, events)
    db.insert_alerts(conn, alerts)

    for a in alerts:
        print(f"  [{a.severity.upper()}] {a.alert_type}: {a.reason}")

    ev, al = dashboard.load_data()
    dashboard.build_charts(ev, al)
    dashboard.build_html(ev, al)
    print(f"Dashboard: {dashboard.DASHBOARD_HTML}")

    high_sev = [a for a in alerts if a.severity == "high"]
    if high_sev:
        summary = f"{len(high_sev)} high-severity security alert(s) detected."
        send_teams_alert(summary, high_sev)

    conn.close()


if __name__ == "__main__":
    run()
