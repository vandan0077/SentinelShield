import json
import os
import sqlite3
from datetime import datetime, timezone

class Storage:
    def __init__(self, db_path: str, json_log_path: str):
        self.db_path = db_path
        self.json_log_path = json_log_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(json_log_path) or ".", exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    user_agent TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    max_severity TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    findings_json TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)")

    def record_event(self, event: dict):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO events
                (ts, ip, method, path, user_agent, decision, reason, categories, max_severity, status_code, findings_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["ts"], event["ip"], event["method"], event["path"],
                    event.get("user_agent", ""), event["decision"], event["reason"],
                    ", ".join(event.get("categories", [])), event["max_severity"],
                    event["status_code"], json.dumps(event.get("findings", [])),
                ),
            )
        with open(self.json_log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def recent(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def summary(self):
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
            flagged = conn.execute("SELECT COUNT(*) FROM events WHERE decision='FLAG'").fetchone()[0]
            by_category = conn.execute("""
                SELECT categories, COUNT(*) AS n FROM events
                WHERE categories <> '' GROUP BY categories ORDER BY n DESC
            """).fetchall()
            top_ips = conn.execute("""
                SELECT ip, COUNT(*) AS n FROM events GROUP BY ip ORDER BY n DESC LIMIT 10
            """).fetchall()
        category_counts = {}
        for row in by_category:
            for category in [x.strip() for x in row[0].split(",") if x.strip()]:
                category_counts[category] = category_counts.get(category, 0) + row[1]
        return {
            "total": total,
            "blocked": blocked,
            "flagged": flagged,
            "allowed": max(total - blocked - flagged, 0),
            "by_category": dict(sorted(category_counts.items(), key=lambda kv: kv[1], reverse=True)),
            "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        }

    @staticmethod
    def now_iso():
        return datetime.now(timezone.utc).isoformat()
