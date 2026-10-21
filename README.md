# 🛡️ UniGuard SIEM

A lightweight, full-stack **Security Information & Event Management (SIEM)** web application for university computer lab environments. Built with Python (Flask) and a dark-themed Tailwind CSS dashboard, it ingests raw access logs in real time, parses them with regex, stores them in SQLite, and automatically detects brute-force login attacks.

---

## 📁 Project Structure

```
UniGuard-SIEM/
├── app.py                  # Flask backend — REST API, regex parser, alert engine, SQLite
├── test_traffic.py         # Interactive traffic generator (normal logins + brute-force burst)
├── file_injector.py        # Streams university_access.log line-by-line to the server
├── university_access.log   # 20-line mock log dataset for testing
├── requirements.txt        # Python dependencies (flask, requests)
└── templates/
    └── index.html          # Dark-theme Tailwind CSS live dashboard
```

---

## ⚙️ Requirements

- Python 3.9+
- pip

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Quick Start

**Step 1 — Start the server**

```bash
cd UniGuard-SIEM
python app.py
```

The server starts at **http://127.0.0.1:5000**

**Step 2 — Open the dashboard**

Navigate to `http://127.0.0.1:5000` in your browser.

**Step 3 — Send test data** *(in a second terminal)*

```bash
# Option A: stream the mock log file (recommended first run)
python file_injector.py

# Option B: interactive traffic generator menu
python test_traffic.py
```

---

## 📡 Log Format

All log sources must POST strings matching this key-value format:

```
LogSource="UniLab" Status="SUCCESS" User="stud_3341" SrcIP="10.10.14.5" Workstation="lab-pc-03"
```

| Field | Values | Description |
|---|---|---|
| `LogSource` | Any string | Origin lab or system identifier |
| `Status` | `SUCCESS` / `FAIL` | Authentication result |
| `User` | Any string | Username attempting login |
| `SrcIP` | IPv4 address | Source IP of the request |
| `Workstation` | Any string | Lab machine identifier |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the live dashboard |
| `POST` | `/api/logs` | Ingest a raw log string |
| `GET` | `/api/logs` | Retrieve latest 200 log events |
| `GET` | `/api/metrics` | Get total / success / fail counters |
| `GET` | `/api/alerts` | Get all IPs currently triggering brute-force alerts |

### Example POST

```bash
curl -X POST http://127.0.0.1:5000/api/logs \
     -H "Content-Type: application/json" \
     -d '{"raw": "LogSource=\"UniLab\" Status=\"FAIL\" User=\"admin_root\" SrcIP=\"10.199.45.12\" Workstation=\"lab-pc-01\""}'
```

### Example Response

```json
{
  "ok": true,
  "parsed": {
    "status": "FAIL",
    "user": "admin_root",
    "src_ip": "10.199.45.12",
    "workstation": "lab-pc-01"
  },
  "timestamp": "2025-07-14T09:31:45.221034",
  "alert": false
}
```

---

## 🧪 Testing Tools

### `file_injector.py` — Log File Streamer

Reads `university_access.log` and POSTs each line to the server with a 0.5 s delay, simulating a live feed.

```bash
python file_injector.py                        # default: http://127.0.0.1:5000
python file_injector.py --delay 1.0            # slow down for demos
python file_injector.py --url http://x.x.x.x:5000  # custom target
```

### `test_traffic.py` — Interactive Traffic Generator

Presents a menu with two modes:

```
[1] Normal Traffic Simulator
    Sends random SUCCESS logins at a configurable interval.
    → Watch the green baseline build up on the dashboard.

[2] Brute-Force Trigger
    Fires 8 rapid FAIL requests from SrcIP 10.199.45.12 within ~1.6 seconds.
    → Watch the dashboard flip to a flashing red alert.

[0] Exit
```

```bash
python test_traffic.py
python test_traffic.py --url http://x.x.x.x:5000
```

---

## 🚨 Brute-Force Detection

The alert engine flags any source IP that generates **5 or more failed logins within a rolling 2-minute window**, regardless of the target username (catches credential-stuffing attacks).

| State | Dashboard |
|---|---|
| No threat | Alerts Panel is grey — *"system nominal"* |
| Threshold breached | Panel turns **bright red** with a pulse animation, shows the offending IP and attack count |
| Window expires | Alert clears automatically — no manual reset needed |

---

## 📊 Dashboard Features

- **Live Event Log Stream** — auto-updating table (newest events on top, new rows flash blue)
- **Metric Cards** — Total Logs Ingested · Successful Logins · Unauthorized Attempts
- **Alerts Panel** — flashes red with a pulse animation on brute-force detection
- **Manual Log Injector** — collapsible dev panel to paste and send raw log strings directly from the browser
- **Simulate 6× FAIL button** — one-click alert trigger built into the dashboard

---

## 🗄️ Database

SQLite database (`uniguard.db`) is created automatically on first run. Schema:

```sql
CREATE TABLE logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT    NOT NULL,   -- 'SUCCESS' or 'FAIL'
    user        TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    workstation TEXT    NOT NULL,
    raw         TEXT    NOT NULL,   -- original log string
    timestamp   TEXT    NOT NULL    -- UTC ISO-8601
);
```

To reset the database and start fresh:

```bash
# Windows
del uniguard.db

# macOS / Linux
rm uniguard.db
```

The database is recreated automatically on the next server start.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 · Flask |
| Database | SQLite (via `sqlite3` stdlib) |
| Log Parsing | Python `re` (regex) |
| Frontend | HTML5 · Tailwind CSS (CDN) · Vanilla JavaScript |
| HTTP Client | `requests` library |
| Concurrency | `threading.Lock` for thread-safe DB writes |
