"""
UniGuard SIEM - Backend
Flask API with SQLite storage, regex log parser, and brute-force alert detection.
"""

import re
import sqlite3
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
DB_PATH = "uniguard.db"
DB_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Regex pattern to extract log fields
# ---------------------------------------------------------------------------
LOG_PATTERN = re.compile(
    r'Status="(?P<status>[^"]+)".*?'
    r'User="(?P<user>[^"]+)".*?'
    r'SrcIP="(?P<src_ip>[^"]+)".*?'
    r'Workstation="(?P<workstation>[^"]+)"',
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                status      TEXT    NOT NULL,
                user        TEXT    NOT NULL,
                src_ip      TEXT    NOT NULL,
                workstation TEXT    NOT NULL,
                raw         TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Alert logic: >= 5 FAIL events from ANY SrcIP within a 2-minute window
# ---------------------------------------------------------------------------

def check_alert(src_ip: str) -> bool:
    """Return True if this SrcIP has accumulated >= 5 FAILs in the last 2 min."""
    window_start = (datetime.utcnow() - timedelta(minutes=2)).isoformat()
    with DB_LOCK:
        with get_db() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS attack_count
                FROM   logs
                WHERE  status    = 'FAIL'
                  AND  src_ip    = ?
                  AND  timestamp >= ?
                """,
                (src_ip, window_start),
            ).fetchone()
    return row["attack_count"] >= 5


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/logs", methods=["POST"])
def ingest_log():
    """
    Accept a raw log string via HTTP POST (JSON body or plain text).
    Expected JSON:  { "raw": "LogSource=... Status=... User=... SrcIP=... Workstation=..." }
    Plain text:     POST body is the raw log string directly.
    """
    # Support both JSON and plain-text payloads
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        raw = payload.get("raw", "")
    else:
        raw = request.get_data(as_text=True)

    if not raw:
        return jsonify({"error": "Empty payload"}), 400

    match = LOG_PATTERN.search(raw)
    if not match:
        return jsonify({"error": "Could not parse log fields from input"}), 422

    status      = match.group("status").upper()
    user        = match.group("user")
    src_ip      = match.group("src_ip")
    workstation = match.group("workstation")
    timestamp   = datetime.utcnow().isoformat()

    with DB_LOCK:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO logs (status, user, src_ip, workstation, raw, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (status, user, src_ip, workstation, raw.strip(), timestamp),
            )
            conn.commit()

    alert = check_alert(src_ip) if status == "FAIL" else False

    return jsonify({
        "ok":        True,
        "parsed":    {"status": status, "user": user, "src_ip": src_ip, "workstation": workstation},
        "timestamp": timestamp,
        "alert":     alert,
    }), 201


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Return the latest 200 log entries (newest first)."""
    with DB_LOCK:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, status, user, src_ip, workstation, timestamp "
                "FROM logs ORDER BY id DESC LIMIT 200"
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Return aggregate counters for the dashboard metric cards."""
    with DB_LOCK:
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
            success = conn.execute(
                "SELECT COUNT(*) AS n FROM logs WHERE status = 'SUCCESS'"
            ).fetchone()["n"]
            fail = conn.execute(
                "SELECT COUNT(*) AS n FROM logs WHERE status = 'FAIL'"
            ).fetchone()["n"]
    return jsonify({"total": total, "success": success, "fail": fail})


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Return all SrcIPs currently triggering the brute-force alert
    (>= 5 FAILs in the last 2 minutes, regardless of username).
    """
    window_start = (datetime.utcnow() - timedelta(minutes=2)).isoformat()
    with DB_LOCK:
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT   src_ip, COUNT(id) AS attack_count
                FROM     logs
                WHERE    status    = 'FAIL'
                  AND    timestamp >= ?
                GROUP BY src_ip
                HAVING   COUNT(id) >= 5
                """,
                (window_start,),
            ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("UniGuard SIEM running at http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
