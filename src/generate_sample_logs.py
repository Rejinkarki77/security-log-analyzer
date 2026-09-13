"""
Generates a synthetic SSH auth log (same line format as a real Linux
/var/log/auth.log) so the pipeline has something realistic to parse.
DEMO DATA ONLY — every IP, username and timestamp below is fake, built
for demonstration purposes.

Scenarios planted on purpose, so the detector has real things to catch:
  1. A brute-force burst: one IP hammering multiple usernames with failed
     logins in a short window.
  2. Credential stuffing success: that same attacking IP eventually gets
     ONE successful login after many failures — the highest-severity signal.
  3. A login from a watchlisted IP range (simulates a known-bad / unusual
     geography source) that succeeds on the first try — no brute force,
     but still worth a human's attention.
  4. A long tail of ordinary, legitimate logins as background noise.

Run: python src/generate_sample_logs.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT_PATH = Path(__file__).parent.parent / "data" / "logs" / "auth.log"

NORMAL_USERS = ["deploy", "jsmith", "abrennan", "svc-backup", "mconnor"]
NORMAL_IPS = ["10.0.0.14", "10.0.0.22", "192.168.1.45", "192.168.1.9", "10.0.0.31"]

ATTACK_IP = "203.0.113.77"
ATTACK_USERS = ["root", "admin", "administrator", "test", "ubuntu", "oracle", "postgres"]

# Simulates a threat-intel watchlist entry (e.g. a known scanning range) —
# in a real deployment this would come from a feed, not be hardcoded.
WATCHLIST_IP = "198.51.100.23"

HOST = "prod-web-01"
SSHD_PID = 18422


def fmt(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def failed_line(ts, user, ip, port):
    return f"{fmt(ts)} {HOST} sshd[{SSHD_PID}]: Failed password for invalid user {user} from {ip} port {port} ssh2"


def accepted_line(ts, user, ip, port):
    return f"{fmt(ts)} {HOST} sshd[{SSHD_PID}]: Accepted password for {user} from {ip} port {port} ssh2"


def main():
    random.seed(7)
    lines = []
    base = datetime(2026, 9, 10, 8, 0, 0)

    # 1. Normal background traffic across the day.
    t = base
    for _ in range(35):
        t += timedelta(minutes=random.randint(4, 40))
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        port = random.randint(40000, 60000)
        # occasional legitimate typo/failed attempt before success
        if random.random() < 0.15:
            lines.append(failed_line(t, user, ip, port))
            t += timedelta(seconds=random.randint(5, 20))
        lines.append(accepted_line(t, user, ip, port))

    # 2. Brute-force burst: ATTACK_IP hammers multiple usernames fast.
    burst_start = base + timedelta(hours=5, minutes=12)
    t = burst_start
    for i in range(14):
        t += timedelta(seconds=random.randint(3, 9))
        user = random.choice(ATTACK_USERS)
        port = random.randint(40000, 60000)
        lines.append(failed_line(t, user, ATTACK_IP, port))

    # 3. Credential stuffing success — the attacker finally gets in.
    t += timedelta(seconds=6)
    lines.append(accepted_line(t, "admin", ATTACK_IP, random.randint(40000, 60000)))

    # 4. Watchlisted IP — no brute force, but flagged purely by source.
    t2 = base + timedelta(hours=7, minutes=45)
    lines.append(accepted_line(t2, "svc-backup", WATCHLIST_IP, random.randint(40000, 60000)))

    # 5. A handful more normal logins after the incident, for realism.
    t = base + timedelta(hours=8)
    for _ in range(10):
        t += timedelta(minutes=random.randint(5, 30))
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        lines.append(accepted_line(t, user, ip, random.randint(40000, 60000)))

    # Sort everything into one chronological log stream, as a real log would be.
    def line_time(line):
        # timestamps have no year, so parse with a fixed placeholder year
        ts_str = line.split(f" {HOST}")[0]
        return datetime.strptime(f"2026 {ts_str}", "%Y %b %d %H:%M:%S")

    lines.sort(key=line_time)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"Generated {len(lines)} log lines -> {OUT_PATH}")


if __name__ == "__main__":
    main()
