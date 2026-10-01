from flask import Flask, jsonify, render_template, request
from .detector import DetectionEngine, SEVERITY_RANK
from .inspector import request_text
from .rate_limiter import RateLimiter
from .storage import Storage
import config


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    detector = DetectionEngine()
    limiter = RateLimiter(config.RATE_LIMIT, config.RATE_WINDOW_SECONDS)
    store = Storage(config.DB_PATH, config.JSON_LOG_PATH)

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "SentinelShield"})

    @app.get("/api/summary")
    def api_summary():
        return jsonify(store.summary())

    @app.get("/api/events")
    def api_events():
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        return jsonify(store.recent(limit))

    @app.post("/inspect")
    def inspect():
        rate_limited, request_count = limiter.check(request.remote_addr or "unknown")
        payload = request_text(request, config.MAX_BODY_BYTES)
        findings = detector.inspect(payload)
        decision, reason = detector.decision(findings, rate_limited)
        max_severity = "NONE" if not findings else max(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity
        status = 200 if decision == "ALLOW" else (429 if reason == "RATE_LIMIT" else 403)
        event = {
            "ts": store.now_iso(),
            "ip": request.remote_addr or "unknown",
            "method": request.method,
            "path": request.path,
            "user_agent": request.headers.get("User-Agent", ""),
            "decision": decision,
            "reason": reason,
            "categories": list(dict.fromkeys(f.category for f in findings)),
            "max_severity": max_severity,
            "status_code": status,
            "request_count_window": request_count,
            "findings": [f.to_dict() for f in findings],
        }
        store.record_event(event)
        return jsonify({
            "decision": decision,
            "reason": reason,
            "status_code": status,
            "request_count_window": request_count,
            "findings": event["findings"],
        }), status

    @app.route("/demo/search", methods=["GET", "POST"])
    def demo_search():
        # Harmless demo target: it displays the submitted search string only.
        q = request.values.get("q", "")
        return jsonify({"demo": "search", "received": q, "note": "This is a non-vulnerable local demo endpoint."})

    @app.route("/demo/login", methods=["GET", "POST"])
    def demo_login():
        user = request.values.get("username", "")
        return jsonify({"demo": "login", "username": user, "authenticated": False,
                        "note": "This endpoint never authenticates; use it only to generate test traffic."})

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
