from urllib.parse import unquote_plus
from flask import Request

SENSITIVE_HEADERS = {"authorization", "cookie"}

def request_text(request: Request, max_body_bytes: int = 65536) -> str:
    parts = [request.path, request.query_string.decode("utf-8", "replace")]
    # Include query parameter values in both raw and once-decoded form.
    for key, values in request.args.lists():
        parts.append(str(key))
        parts.extend(str(v) for v in values)
        parts.extend(unquote_plus(str(v)) for v in values)
    raw = request.get_data(cache=True)[:max_body_bytes]
    if raw:
        decoded = raw.decode("utf-8", "replace")
        parts.append(decoded)
        parts.append(unquote_plus(decoded))
    for name, value in request.headers.items():
        lname = name.lower()
        if lname in SENSITIVE_HEADERS:
            parts.append(f"{name}:<redacted>")
        else:
            parts.append(f"{name}:{value}")
    return "\n".join(parts)
