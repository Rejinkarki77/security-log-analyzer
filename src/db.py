"""
SQLite storage layer. Same rationale as the invoice project: zero setup
to run, and the schema/queries port directly to a real SQL Server/Postgres
deployment with no changes.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "db" / "security_events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    port INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT,
    timestamp TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def reset_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    return get_connection()


def insert_events(conn, events):
    conn.executemany(
        "INSERT INTO login_events (timestamp, event_type, username, source_ip, port) VALUES (?, ?, ?, ?, ?)",
        [(e.timestamp.isoformat(), e.event_type, e.username, e.source_ip, e.port) for e in events],
    )
    conn.commit()


def insert_alerts(conn, alerts):
    conn.executemany(
        "INSERT INTO alerts (severity, alert_type, source_ip, username, timestamp, reason) VALUES (?, ?, ?, ?, ?, ?)",
        [(a.severity, a.alert_type, a.source_ip, a.username, a.timestamp.isoformat(), a.reason) for a in alerts],
    )
    conn.commit()
