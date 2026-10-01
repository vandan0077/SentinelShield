# SentinelShield: Advanced Intrusion Detection & Web Protection System

## Abstract
SentinelShield is a lightweight educational intrusion detection and web-protection system that demonstrates how HTTP request inspection, signature-based detection, rate limiting, event logging, and dashboarding can be combined into a practical defensive workflow. The system is designed for an authorized local lab and does not execute received payloads.

## Objectives
1. Inspect HTTP request components from a security perspective.
2. Detect common attack indicators using rule-based signatures.
3. Apply IP-based request-rate monitoring.
4. Log decisions and findings for analysis.
5. Present summarized events through a dashboard.
6. Measure detection results with controlled test cases.

## System Architecture
Client/Test Request → Flask Endpoint → Request Inspector → Detection Engine + Rate Limiter → Decision → SQLite/JSON Log → Dashboard APIs → Web Dashboard.

## Modules
### Request Inspector
Collects method, path, query string, request body (size-limited), and non-sensitive headers.

### Detection Engine
Checks normalized request content against documented regular-expression signatures.

### Behavior Monitor
Counts requests per source IP inside a sliding time window.

### Decision Engine
Returns ALLOW, FLAG, or BLOCK based on rule severity and rate-limit state.

### Logging
Stores timestamp, IP, path, decision, reason, severity, and findings in SQLite and JSON Lines format.

### Dashboard
Shows event totals, category distribution, repeatedly observed IPs, and recent events.

## Testing
Use `scripts/run_tests.py` after starting the application. The script runs benign and malicious-looking test cases against `127.0.0.1` only.

## Detection Accuracy
Fill this section from the controlled test output. Use:
- Accuracy = (TP + TN) / Total
- False Positive Rate = FP / (FP + TN)
- False Negative Rate = FN / (FN + TP)

**Important:** Accuracy measured on the small lab test set is not equivalent to real-world WAF effectiveness.

## False Positives / False Negatives
Document any legitimate requests incorrectly flagged and any test indicators that were missed. Explain which rule was adjusted and why.

## Limitations
- Rule-based detection can be bypassed by inputs that do not match current patterns.
- In-memory rate limiting resets when the application restarts.
- The project does not claim production-grade WAF coverage.
- It should be deployed only in an authorized testing environment.

## Future Scope
- Rule versioning and severity tuning.
- Persistent rate-limit state.
- Structured alerting (email/SIEM integration).
- Better request normalization and parser-aware inspection.
- Role-based dashboard access.
- Additional defensive signatures and unit tests.

## Conclusion
SentinelShield demonstrates the end-to-end defensive workflow of request inspection, threat detection, rate limiting, logging, and dashboard visualization in a controlled educational environment.
