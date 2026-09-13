"""
Builds a static, self-contained HTML dashboard from the SQLite data —
double-click to view, no server needed.
"""

import sqlite3
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from db import DB_PATH

OUT_DIR = Path(__file__).parent.parent / "docs"
CHART_FAILED_OVER_TIME = OUT_DIR / "chart_failed_logins_timeline.png"
CHART_TOP_IPS = OUT_DIR / "chart_top_source_ips.png"
DASHBOARD_HTML = OUT_DIR / "dashboard.html"

SEVERITY_COLOR = {"high": "#a12626", "medium": "#8a6300", "low": "#555"}


def load_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    events = [dict(r) for r in conn.execute("SELECT * FROM login_events ORDER BY timestamp")]
    alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY severity, timestamp")]
    conn.close()
    return events, alerts


def build_charts(events, alerts):
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Failed logins over time (hourly buckets)
    by_hour = defaultdict(int)
    for e in events:
        if e["event_type"] == "failed":
            hour = e["timestamp"][:13]  # YYYY-MM-DDTHH
            by_hour[hour] += 1
    hours = sorted(by_hour)
    plt.figure(figsize=(8, 4))
    plt.plot(hours, [by_hour[h] for h in hours], marker="o", color="#a12626")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Failed login attempts")
    plt.title("Failed logins over time")
    plt.tight_layout()
    plt.savefig(CHART_FAILED_OVER_TIME, dpi=150)
    plt.close()

    # Top source IPs by failed attempts
    by_ip = defaultdict(int)
    for e in events:
        if e["event_type"] == "failed":
            by_ip[e["source_ip"]] += 1
    top_ips = sorted(by_ip, key=by_ip.get, reverse=True)[:8]
    plt.figure(figsize=(8, 4.5))
    plt.barh(top_ips[::-1], [by_ip[ip] for ip in top_ips[::-1]], color="#2f6f4f")
    plt.xlabel("Failed login attempts")
    plt.title("Top source IPs by failed logins")
    plt.tight_layout()
    plt.savefig(CHART_TOP_IPS, dpi=150)
    plt.close()


def build_html(events, alerts):
    total_events = len(events)
    failed = sum(1 for e in events if e["event_type"] == "failed")
    accepted = total_events - failed
    high_sev = sum(1 for a in alerts if a["severity"] == "high")
    medium_sev = sum(1 for a in alerts if a["severity"] == "medium")

    def alert_row(a):
        color = SEVERITY_COLOR.get(a["severity"], "#555")
        return f"""
        <tr>
            <td><span class="sev" style="background:{color}">{a['severity'].upper()}</span></td>
            <td>{a['alert_type'].replace('_', ' ')}</td>
            <td>{a['source_ip']}</td>
            <td>{a['username'] or '-'}</td>
            <td>{a['timestamp']}</td>
            <td>{a['reason']}</td>
        </tr>"""

    alerts_html = "\n".join(alert_row(a) for a in alerts) or "<tr><td colspan='6'>No alerts.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Security Log Analyzer Dashboard</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 0; background: #101418; color: #e8e8e8; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px; }}
  h1 {{ margin-bottom: 4px; }}
  .sub {{ color: #9aa4ae; margin-top: 0; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 24px 0; }}
  .stat {{ background: #1a2028; border-radius: 10px; padding: 16px 20px; min-width: 150px; border: 1px solid #232b35; }}
  .stat .num {{ font-size: 26px; font-weight: 700; }}
  .stat .label {{ color: #9aa4ae; font-size: 13px; }}
  .charts {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 24px 0; }}
  .charts img {{ max-width: 100%; border-radius: 10px; background: #fff; padding: 8px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a2028; border-radius: 10px; overflow: hidden; border: 1px solid #232b35; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #232b35; font-size: 13px; }}
  th {{ background: #202834; }}
  .sev {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #fff; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Security Log Analyzer Dashboard</h1>
  <p class="sub">Auto-generated from data/db/security_events.db — demo data, not a real environment.</p>

  <div class="stats">
    <div class="stat"><div class="num">{total_events}</div><div class="label">Login events</div></div>
    <div class="stat"><div class="num">{failed}</div><div class="label">Failed attempts</div></div>
    <div class="stat"><div class="num">{accepted}</div><div class="label">Successful logins</div></div>
    <div class="stat"><div class="num">{high_sev}</div><div class="label">High-severity alerts</div></div>
    <div class="stat"><div class="num">{medium_sev}</div><div class="label">Medium-severity alerts</div></div>
  </div>

  <div class="charts">
    <img src="chart_failed_logins_timeline.png" alt="Failed logins over time" />
    <img src="chart_top_source_ips.png" alt="Top source IPs" />
  </div>

  <h2>Alerts</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Type</th><th>Source IP</th><th>User</th><th>Time</th><th>Reason</th></tr>
    </thead>
    <tbody>
      {alerts_html}
    </tbody>
  </table>
</div>
</body>
</html>"""
    DASHBOARD_HTML.write_text(html)


def main():
    events, alerts = load_data()
    build_charts(events, alerts)
    build_html(events, alerts)
    print(f"Dashboard written to {DASHBOARD_HTML}")


if __name__ == "__main__":
    main()
