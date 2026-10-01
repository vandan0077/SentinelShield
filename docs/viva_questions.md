# Viva Questions & Answers

## 1. What is a WAF?
A Web Application Firewall inspects web traffic and applies rules to detect or block suspicious application-layer requests.

## 2. What is IDS?
An Intrusion Detection System identifies suspicious or malicious activity and produces alerts/logs. Blocking is normally associated with prevention controls such as IPS/WAF behavior.

## 3. Why is request normalization important?
Attack strings may be URL-encoded or represented in more than one form. Normalization lets the detector inspect a representation that is closer to what the application interprets.

## 4. Why use rate limiting?
It reduces abusive request volume and makes automated brute-force or flooding behavior easier to detect.

## 5. What is a false positive?
A benign request incorrectly classified as suspicious.

## 6. What is a false negative?
A malicious test case that the detector fails to identify.

## 7. Why use both SQLite and JSONL logs?
SQLite supports structured queries and dashboard summaries, while JSONL provides a simple append-only audit format useful for inspection/export.

## 8. Is this production-ready?
No. It is an educational implementation. Production WAFs require broader rule coverage, secure deployment, parser-aware normalization, distributed rate limiting, authentication, monitoring, and extensive testing.
