from dataclasses import dataclass, asdict
from typing import Iterable
from .rules import compiled_rules

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    matched: str

    def to_dict(self):
        return asdict(self)

class DetectionEngine:
    def __init__(self):
        self.rules = compiled_rules()

    def inspect(self, payload: str) -> list[Finding]:
        findings: list[Finding] = []
        payload = payload or ""
        for rule, patterns in self.rules:
            for pattern in patterns:
                match = pattern.search(payload)
                if match:
                    findings.append(Finding(
                        rule.rule_id, rule.category, rule.severity,
                        rule.description, match.group(0)[:160]
                    ))
                    break
        return findings

    @staticmethod
    def decision(findings: Iterable[Finding], rate_limited: bool = False) -> tuple[str, str]:
        findings = list(findings)
        if rate_limited:
            return "BLOCK", "RATE_LIMIT"
        if not findings:
            return "ALLOW", "NONE"
        highest = max(findings, key=lambda f: SEVERITY_RANK[f.severity])
        if SEVERITY_RANK[highest.severity] >= 3:
            return "BLOCK", highest.category
        return "FLAG", highest.category
