import os

HOST = os.getenv("SENTINEL_HOST", "127.0.0.1")
PORT = int(os.getenv("SENTINEL_PORT", "5000"))
DEBUG = os.getenv("SENTINEL_DEBUG", "0") == "1"
RATE_LIMIT = int(os.getenv("SENTINEL_RATE_LIMIT", "20"))
RATE_WINDOW_SECONDS = int(os.getenv("SENTINEL_RATE_WINDOW", "60"))
MAX_BODY_BYTES = int(os.getenv("SENTINEL_MAX_BODY", str(64 * 1024)))
DB_PATH = os.getenv("SENTINEL_DB", "data/sentinelshield.sqlite3")
JSON_LOG_PATH = os.getenv("SENTINEL_JSON_LOG", "logs/events.jsonl")
