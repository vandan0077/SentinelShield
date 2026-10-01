# SentinelShield

Educational Intrusion Detection & Web Protection System for an authorized local cybersecurity lab.

## Features
- HTTP request inspection
- Signature-based detection for SQL injection, XSS, traversal/LFI, command-injection indicators, and suspicious encoding
- Sliding-window IP rate limiting
- ALLOW / FLAG / BLOCK decisions
- SQLite + JSONL audit logging
- Browser dashboard with event summaries
- Controlled local test script and unit tests

## 1. Requirements
- Python 3.11+ recommended
- Windows, Linux, or macOS

## 2. Setup (Windows PowerShell)
```powershell
cd SentinelShield
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```
Open http://127.0.0.1:5000

## 3. Setup (Linux/macOS)
```bash
cd SentinelShield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

## 4. Run the controlled tests
Keep the server running in one terminal. In another terminal:
```bash
python scripts/run_tests.py
```

## 5. Configuration
Environment variables:
- `SENTINEL_RATE_LIMIT` default `20`
- `SENTINEL_RATE_WINDOW` default `60`
- `SENTINEL_MAX_BODY` default `65536`
- `SENTINEL_HOST` default `127.0.0.1`
- `SENTINEL_PORT` default `5000`

## 6. Data
- SQLite: `data/sentinelshield.sqlite3`
- JSONL: `logs/events.jsonl`

## 7. Safety / Scope
This implementation is defensive and intended for authorized local testing. The demo endpoints never execute submitted values, and the included test traffic targets only `127.0.0.1`.
