from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    description: str
    patterns: tuple[str, ...]

RULES = [
    Rule(
        "SS-SQLI-001", "SQL Injection", "HIGH",
        "SQL syntax or tautology-like content commonly associated with injection testing.",
        (
            r"(?i)\bunion\s+(?:all\s+)?select\b",
            r"(?i)\b(?:or|and)\s+['\"`]?\w+['\"`]?\s*=\s*['\"`]?\w+['\"`]?",
            r"(?i)\bsleep\s*\(",
            r"(?i)\bbenchmark\s*\(",
            r"(?i)\binformation_schema\b",
        ),
    ),
    Rule(
        "SS-XSS-001", "Cross-Site Scripting", "HIGH",
        "Markup/script-like content or event-handler syntax associated with XSS testing.",
        (
            r"(?i)<\s*script\b",
            r"(?i)javascript\s*:",
            r"(?i)\bon(?:error|load|click|mouseover)\s*=",
            r"(?i)<\s*svg\b[^>]*\bonload\s*=",
        ),
    ),
    Rule(
        "SS-TRV-001", "Directory Traversal / LFI", "HIGH",
        "Traversal sequences or sensitive local-file scheme/path references.",
        (
            r"\.\./",
            r"\.\.\\",
            r"(?i)%2e%2e(?:%2f|/|%5c)",
            r"(?i)%252e%252e",
            r"(?i)(?:/|\\)etc(?:/|\\)passwd\b",
            r"(?i)php://(?:filter|input|memory)",
        ),
    ),
    Rule(
        "SS-CMD-001", "Command Injection", "CRITICAL",
        "Shell metacharacter patterns commonly used in command-injection test payloads.",
        (
            r"(?i)(?:^|[;&|])\s*(?:id|whoami|uname|cat|curl|wget)\b",
            r"`[^`]{1,200}`",
            r"\$\([^)]{1,200}\)",
        ),
    ),
    Rule(
        "SS-ENC-001", "Suspicious Encoding", "MEDIUM",
        "Repeated percent-encoding that can be used to hide request content from naive filters.",
        (
            r"(?i)(?:%25){2,}",
            r"(?i)(?:%[0-9a-f]{2}){8,}",
        ),
    ),
]

def compiled_rules():
    return [(rule, tuple(re.compile(p) for p in rule.patterns)) for rule in RULES]
