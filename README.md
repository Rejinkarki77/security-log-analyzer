# Security Log Analyzer

A small SOC-analyst-style tool that ingests SSH authentication logs, detects
brute-force attacks, credential-stuffing successes, and logins from
watchlisted IPs, then produces a dashboard an analyst could actually triage
from. Built as a focused 3-day project to demonstrate practical, entry-level
security engineering: log parsing, rule-based detection logic, data storage,
and clear reporting — not just theory.

**Live demo dashboard:** see `docs/dashboard_screenshot.png`, or run the
project yourself in a few minutes (instructions below).

## Why this project

Most SOC and security-analyst work isn't exotic threat hunting — it's
reading logs, applying clear detection rules, and knowing which alerts
actually matter. This project simulates that loop end to end: raw log →
parsed events → detection rules → a dashboard a human can act on.

## What it does

1. **Generates realistic sample data** — a synthetic `auth.log` in standard
   OpenSSH format (the same format as a real `/var/log/auth.log`), with a
   brute-force attack, a successful credential-stuffing login, and a
   watchlisted-IP login deliberately planted alongside normal traffic.
2. **Parses** every login attempt (failed and accepted) into structured
   events with regex written against the real OpenSSH log format.
3. **Detects**, using explainable, threshold-based rules (not a black-box
   model — every alert says exactly why it fired):
   - **Brute force** — 5+ failed logins from one IP inside a 10-minute
     window.
   - **Credential stuffing success** (highest severity) — a *successful*
     login from an IP that was already flagged for brute-forcing.
   - **Watchlisted source** — a successful login from an IP on a simulated
     threat-intel watchlist.
4. **Stores** every event and alert in SQLite (schema and queries port
   directly to a real SQL Server/Postgres deployment).
5. **Builds a dashboard** (`docs/dashboard.html`) — dark, analyst-style UI
   with stat tiles, a failed-logins timeline, a top-source-IPs chart, and a
   severity-coded alerts table.
6. **Optionally alerts Microsoft Teams** via an Incoming Webhook when a
   high-severity alert fires.

## Skills demonstrated

| Area | Where |
|---|---|
| Python scripting & regex | `parse_logs.py` — OpenSSH log parsing |
| Cybersecurity concepts | `detect.py` — brute force, credential stuffing, threat-intel watchlisting |
| SQL / data modeling | `db.py` — SQLite schema for events + alerts |
| Data visualization / reporting | `dashboard.py` — matplotlib charts + HTML dashboard |
| Automation / alerting | `notify.py` — Teams webhook integration |
| Testing | `tests/` — 10 pytest unit tests covering parsing and detection logic |
| IT support mindset | Everything runs from one command, no infra to stand up |

Maps directly to the Cybersecurity, Python, SQL, and IT Support areas on my
LinkedIn profile.

## How it was built (3-day scope)

- **Day 1 — Data & parsing:** designed the synthetic log generator
  (`generate_sample_logs.py`) against the real OpenSSH `auth.log` format,
  then wrote the regex-based parser (`parse_logs.py`) and confirmed it
  correctly extracted timestamp, event type, username, source IP, and port.
- **Day 2 — Detection & storage:** wrote the three rule-based detectors
  (`detect.py`) with explainable thresholds, built the SQLite storage layer
  (`db.py`), wired them together in `pipeline.py`, and wrote the unit test
  suite (`tests/`) to lock the logic in.
- **Day 3 — Dashboard, alerting & polish:** built the analyst dashboard
  (`dashboard.py`), added the optional Teams alert (`notify.py`), verified
  the whole pipeline end to end with a fresh screenshot, and wrote this
  README, `.env.example`, `.gitignore`, and packaging.

## Running it

```bash
# 1. Set up a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt      # Windows: python -m pip install -r requirements.txt

# 3. Generate sample data and run the full pipeline
python src/generate_sample_logs.py
python src/pipeline.py

# 4. Open the dashboard
open docs/dashboard.html             # Windows: start docs\dashboard.html
```

To test the optional Teams alert, copy `.env.example` to `.env`, add a real
Incoming Webhook URL, and export it before running `pipeline.py`.

## Running the tests

```bash
python -m pytest tests/ -v
```

10 tests covering log parsing (valid lines, malformed/unrelated lines,
timestamp handling) and detection logic (threshold boundaries, time-window
edges, severity ordering).

## Honesty notes

- The Teams webhook (`notify.py`) is written against Microsoft's documented
  Incoming Webhook payload format but hasn't been tested against a real
  tenant, since I don't have one to test against — it's ready to connect,
  not yet proven in production. Everything else (parsing, detection,
  storage, dashboard) has been run and verified end to end on real
  generated data.
- The watchlist IP and attack IP use the RFC 5737 documentation ranges
  (`203.0.113.0/24`, `198.51.100.0/24`), which are reserved for
  documentation and will never appear on the real internet — a deliberate
  choice so the sample data is realistic without pointing at anything real.
- "Threat-intel watchlist" here is a hardcoded set standing in for a real
  feed (e.g. AbuseIPDB); see "What I'd build next" below.

## What I'd build next

- Pull the watchlist from a live threat-intel API (AbuseIPDB, or an
  internal blocklist) instead of a hardcoded set.
- Add a statistical/behavioral anomaly detector (e.g. login-time-of-day
  baselining) as a v2 alongside the rule-based detectors, once there's
  enough historical data to baseline against.
- Support ingesting logs continuously (tail -f style) instead of a
  one-shot batch run, for near-real-time alerting.
- Add geo-IP lookups to the dashboard so analysts can see attack origin at
  a glance.

## Project structure

```
security-log-analyzer/
├── src/
│   ├── generate_sample_logs.py   # synthetic OpenSSH auth.log generator
│   ├── parse_logs.py             # regex-based log parser
│   ├── detect.py                 # brute force / cred stuffing / watchlist rules
│   ├── db.py                     # SQLite storage
│   ├── dashboard.py              # charts + HTML dashboard builder
│   ├── notify.py                 # Teams webhook alerting
│   └── pipeline.py               # orchestrates the full run
├── tests/
│   ├── test_parse_logs.py
│   └── test_detect.py
├── data/
│   ├── logs/                     # generated auth.log lives here
│   └── db/                       # SQLite database lives here
├── docs/
│   ├── dashboard.html            # generated dashboard (open this)
│   ├── chart_failed_logins_timeline.png
│   ├── chart_top_source_ips.png
│   └── dashboard_screenshot.png
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE
```

## Author

Rejin Karki — Dublin, Ireland
[linkedin.com/in/rejinkarki](https://www.linkedin.com/in/rejinkarki)
