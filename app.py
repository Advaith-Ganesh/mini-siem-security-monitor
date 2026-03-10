from __future__ import annotations

import csv
import ipaddress
import math
import os
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from flask import Flask, flash, g, redirect, render_template, request, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "siem.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "mini-siem-demo-secret"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# -----------------------------
# Database helpers
# -----------------------------


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: Optional[BaseException]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()



def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    with open(os.path.join(BASE_DIR, "schema.sql"), "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
    db.close()


# -----------------------------
# Models / parsing helpers
# -----------------------------

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%b/%Y:%H:%M:%S",
]

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class ParsedEvent:
    timestamp: datetime
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    status: str
    location: Optional[str]
    raw_log: str


PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def classify_location(ip_str: Optional[str]) -> str:
    if not ip_str:
        return "Unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network in PRIVATE_NETS:
            if ip_obj in network:
                return "Internal Network"
        first_octet = int(ip_str.split(".")[0]) if "." in ip_str else 0
        if 1 <= first_octet <= 49:
            return "North America"
        if 50 <= first_octet <= 99:
            return "Europe"
        if 100 <= first_octet <= 149:
            return "Middle East / Africa"
        if 150 <= first_octet <= 199:
            return "Asia Pacific"
        return "Latin America"
    except ValueError:
        return "Unknown"



def parse_timestamp(raw: str) -> Optional[datetime]:
    raw = raw.strip()

    # Apache style: 10/Mar/2026:12:20:01
    apache_match = re.search(r"\b(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\b", raw)
    if apache_match:
        day, mon, year, hms = apache_match.groups()
        return datetime.strptime(f"{day}/{mon}/{year}:{hms}", "%d/%b/%Y:%H:%M:%S")

    # Syslog style: Mar 10 12:20:01
    syslog_match = re.search(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b", raw)
    if syslog_match:
        mon, day, hms = syslog_match.groups()
        year = datetime.utcnow().year
        return datetime.strptime(f"{year}-{MONTHS[mon]:02d}-{int(day):02d} {hms}", "%Y-%m-%d %H:%M:%S")

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw[:19], fmt)
        except ValueError:
            continue

    iso_match = re.search(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}Z?\b", raw)
    if iso_match:
        cleaned = iso_match.group(0).replace("Z", "")
        cleaned = cleaned.replace("T", " ")
        try:
            return datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None



def parse_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None

    ts = parse_timestamp(line) or datetime.utcnow()
    lower = line.lower()

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    ip = ip_match.group(0) if ip_match else None

    user_match = re.search(r"\buser(?:name)?[=: ]+([A-Za-z0-9._-]+)", line, flags=re.IGNORECASE)
    if not user_match:
        user_match = re.search(r"for\s+([A-Za-z0-9._-]+)\s+from", line)
    username = user_match.group(1) if user_match else None

    location = classify_location(ip)

    if "accepted password" in lower or ("login" in lower and "success" in lower) or "status=200" in lower:
        return ParsedEvent(ts, "login", username, ip, "success", location, line)

    if "failed password" in lower or ("login" in lower and "failed" in lower) or "status=401" in lower or "status=403" in lower:
        return ParsedEvent(ts, "login", username, ip, "failure", location, line)

    if any(token in lower for token in ["get ", "post ", "request", "status="]):
        return ParsedEvent(ts, "web_request", username, ip, "observed", location, line)

    return ParsedEvent(ts, "generic", username, ip, "observed", location, line)


# -----------------------------
# Detection logic
# -----------------------------


def insert_event(db: sqlite3.Connection, event: ParsedEvent) -> int:
    cur = db.execute(
        """
        INSERT INTO events (timestamp, event_type, username, source_ip, status, location, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.timestamp.isoformat(sep=" "),
            event.event_type,
            event.username,
            event.source_ip,
            event.status,
            event.location,
            event.raw_log,
        ),
    )
    return int(cur.lastrowid)



def create_alert(db: sqlite3.Connection, alert_type: str, severity: str, description: str,
                 source_ip: Optional[str], username: Optional[str], related_event_id: Optional[int],
                 detected_at: datetime) -> None:
    db.execute(
        """
        INSERT INTO alerts (detected_at, alert_type, severity, description, source_ip, username, related_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detected_at.isoformat(sep=" "),
            alert_type,
            severity,
            description,
            source_ip,
            username,
            related_event_id,
        ),
    )



def distance_km_by_region(loc1: str, loc2: str) -> int:
    if loc1 == loc2:
        return 0
    pairs = {
        frozenset(["North America", "Europe"]): 6000,
        frozenset(["Europe", "Middle East / Africa"]): 4500,
        frozenset(["Europe", "Asia Pacific"]): 9500,
        frozenset(["North America", "Asia Pacific"]): 11000,
        frozenset(["Middle East / Africa", "Asia Pacific"]): 8000,
        frozenset(["Latin America", "Europe"]): 8500,
        frozenset(["Latin America", "North America"]): 4500,
    }
    return pairs.get(frozenset([loc1, loc2]), 7000)



def detect_brute_force(db: sqlite3.Connection) -> None:
    rows = db.execute(
        """
        SELECT source_ip, username, MIN(timestamp) AS start_ts, MAX(timestamp) AS end_ts,
               COUNT(*) AS fail_count, MAX(id) AS event_id
        FROM events
        WHERE event_type = 'login' AND status = 'failure' AND source_ip IS NOT NULL
        GROUP BY source_ip, username, strftime('%Y-%m-%d %H:%M', timestamp)
        HAVING fail_count >= 5
        """
    ).fetchall()
    for row in rows:
        create_alert(
            db,
            "Brute Force Login",
            "high",
            f"{row['fail_count']} failed logins from IP {row['source_ip']} against user {row['username'] or 'unknown'} in a short period.",
            row["source_ip"],
            row["username"],
            row["event_id"],
            datetime.utcnow(),
        )



def detect_password_spraying(db: sqlite3.Connection) -> None:
    rows = db.execute(
        """
        SELECT source_ip, COUNT(DISTINCT COALESCE(username, raw_log)) AS user_count,
               COUNT(*) AS attempts, MAX(id) AS event_id
        FROM events
        WHERE event_type = 'login' AND status = 'failure' AND source_ip IS NOT NULL
        GROUP BY source_ip, strftime('%Y-%m-%d %H:%M', timestamp)
        HAVING user_count >= 4 AND attempts >= 6
        """
    ).fetchall()
    for row in rows:
        create_alert(
            db,
            "Password Spraying",
            "high",
            f"IP {row['source_ip']} failed against {row['user_count']} different accounts in a short window.",
            row["source_ip"],
            None,
            row["event_id"],
            datetime.utcnow(),
        )



def detect_suspicious_ip(db: sqlite3.Connection) -> None:
    rows = db.execute(
        """
        SELECT source_ip,
               SUM(CASE WHEN status='failure' THEN 1 ELSE 0 END) AS failures,
               SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS successes,
               COUNT(*) AS total,
               MAX(id) AS event_id
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        HAVING total >= 8 AND failures * 1.0 / total >= 0.7
        """
    ).fetchall()
    for row in rows:
        create_alert(
            db,
            "Suspicious IP Behaviour",
            "medium",
            f"IP {row['source_ip']} generated {row['total']} events with unusually high failure ratio.",
            row["source_ip"],
            None,
            row["event_id"],
            datetime.utcnow(),
        )



def detect_impossible_travel(db: sqlite3.Connection) -> None:
    rows = db.execute(
        """
        SELECT id, timestamp, username, source_ip, location
        FROM events
        WHERE event_type='login' AND status='success' AND username IS NOT NULL AND location IS NOT NULL
        ORDER BY username, timestamp
        """
    ).fetchall()

    grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[row["username"]].append(row)

    for username, user_events in grouped.items():
        for i in range(1, len(user_events)):
            prev = user_events[i - 1]
            curr = user_events[i]
            t1 = datetime.fromisoformat(prev["timestamp"])
            t2 = datetime.fromisoformat(curr["timestamp"])
            hours = max((t2 - t1).total_seconds() / 3600, 0.1)
            distance = distance_km_by_region(prev["location"], curr["location"])
            speed = distance / hours
            if prev["location"] != curr["location"] and speed > 900:
                create_alert(
                    db,
                    "Impossible Travel Login",
                    "high",
                    f"User {username} logged in from {prev['location']} then {curr['location']} within {hours:.1f} hours.",
                    curr["source_ip"],
                    username,
                    curr["id"],
                    datetime.utcnow(),
                )



def detect_dos_pattern(db: sqlite3.Connection) -> None:
    rows = db.execute(
        """
        SELECT source_ip, strftime('%Y-%m-%d %H:%M', timestamp) AS minute_bucket,
               COUNT(*) AS request_count, MAX(id) AS event_id
        FROM events
        WHERE event_type='web_request' AND source_ip IS NOT NULL
        GROUP BY source_ip, minute_bucket
        HAVING request_count >= 30
        """
    ).fetchall()
    for row in rows:
        create_alert(
            db,
            "Too Many Requests / DoS Pattern",
            "critical",
            f"IP {row['source_ip']} made {row['request_count']} requests within one minute.",
            row["source_ip"],
            None,
            row["event_id"],
            datetime.utcnow(),
        )



def dedupe_alerts(db: sqlite3.Connection) -> None:
    db.execute(
        """
        DELETE FROM alerts
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM alerts
            GROUP BY alert_type, COALESCE(source_ip, ''), COALESCE(username, ''), description
        )
        """
    )



def run_detections(db: sqlite3.Connection) -> None:
    detect_brute_force(db)
    detect_password_spraying(db)
    detect_suspicious_ip(db)
    detect_impossible_travel(db)
    detect_dos_pattern(db)
    dedupe_alerts(db)
    db.commit()


# -----------------------------
# Routes
# -----------------------------


@app.route("/")
def index():
    db = get_db()
    counts = {
        "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "alerts": db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "critical": db.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'").fetchone()[0],
        "high": db.execute("SELECT COUNT(*) FROM alerts WHERE severity='high'").fetchone()[0],
    }

    recent_alerts = db.execute(
        "SELECT * FROM alerts ORDER BY detected_at DESC LIMIT 10"
    ).fetchall()
    recent_events = db.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 12"
    ).fetchall()
    timeline = db.execute(
        """
        SELECT substr(detected_at, 1, 13) || ':00' AS bucket, COUNT(*) AS total
        FROM alerts
        GROUP BY bucket
        ORDER BY bucket ASC
        LIMIT 24
        """
    ).fetchall()
    top_ips = db.execute(
        """
        SELECT source_ip, COUNT(*) AS total
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY total DESC
        LIMIT 8
        """
    ).fetchall()

    return render_template(
        "dashboard.html",
        counts=counts,
        recent_alerts=recent_alerts,
        recent_events=recent_events,
        timeline=timeline,
        top_ips=top_ips,
    )


@app.route("/upload", methods=["POST"])
def upload_logs():
    file = request.files.get("logfile")
    if not file or not file.filename:
        flash("Choose a log file first.", "error")
        return redirect(url_for("index"))

    content = file.read().decode("utf-8", errors="ignore")
    db = get_db()
    inserted = 0
    for line in content.splitlines():
        event = parse_line(line)
        if event:
            insert_event(db, event)
            inserted += 1
    db.commit()
    run_detections(db)
    flash(f"Uploaded successfully. Parsed {inserted} log lines.", "success")
    return redirect(url_for("index"))


@app.route("/seed")
def seed_demo_data():
    db = get_db()
    sample_lines = [
        "2026-03-10 08:00:01 sshd Failed password for admin from 23.45.12.8 port 22",
        "2026-03-10 08:00:12 sshd Failed password for admin from 23.45.12.8 port 22",
        "2026-03-10 08:00:18 sshd Failed password for admin from 23.45.12.8 port 22",
        "2026-03-10 08:00:27 sshd Failed password for admin from 23.45.12.8 port 22",
        "2026-03-10 08:00:41 sshd Failed password for admin from 23.45.12.8 port 22",
        "2026-03-10 08:05:01 sshd Failed password for alice from 77.11.9.3 port 22",
        "2026-03-10 08:05:08 sshd Failed password for bob from 77.11.9.3 port 22",
        "2026-03-10 08:05:12 sshd Failed password for carol from 77.11.9.3 port 22",
        "2026-03-10 08:05:18 sshd Failed password for dave from 77.11.9.3 port 22",
        "2026-03-10 09:00:00 login success username=james ip=55.33.10.2",
        "2026-03-10 11:00:00 login success username=james ip=166.45.22.9",
    ]
    sample_lines.extend(
        [f"2026-03-10 10:10:{i:02d} GET /index.html status=200 ip=188.90.2.10" for i in range(35)]
    )
    for line in sample_lines:
        event = parse_line(line)
        if event:
            insert_event(db, event)
    db.commit()
    run_detections(db)
    flash("Demo attack data inserted.", "success")
    return redirect(url_for("index"))


@app.route("/reset")
def reset_data():
    db = get_db()
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM events")
    db.commit()
    flash("Database cleared.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True)
