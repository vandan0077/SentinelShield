# SentinelShield – Practical Journal

## Experiment 1 – System Architecture
**Purpose:** Understand the workflow Request → Inspector → Detection Rules → Decision → Logging → Dashboard.

**Observation:** The local Flask service receives a request, builds a normalized inspection string, checks rules, evaluates rate limits, records an event in SQLite/JSONL, and returns an allow/flag/block decision.

**Screenshot:** Add a screenshot of the dashboard and architecture diagram here.

## Experiment 2 – HTTP Request Inspection
**Purpose:** Break a request into method, path, query parameters, headers, and body.

**Test:** Use `/inspect` with a normal request and compare it with a malicious-looking test payload.

**Observation:** URL/query/body/header content can contain indicators that match detection signatures.

## Experiment 3 – Signature Detection
Test categories:
- SQL Injection
- Cross-Site Scripting
- Directory Traversal / LFI
- Command Injection
- Suspicious Encoding

Record for each test: input, expected category, actual category, decision, severity, and timestamp.

## Experiment 4 – Rate Limiting
**Purpose:** Observe how repeated requests from the same local IP are counted within a time window.

Default configuration: 20 requests per 60 seconds.

**Observation:** Requests above the configured threshold return a rate-limit block and generate a logged event.

## Experiment 5 – Log Analysis
Inspect `data/sentinelshield.sqlite3` through the dashboard or a SQLite viewer. Compare total, blocked, flagged, and allowed requests. Identify repeated IP activity.

## Experiment 6 – Reporting
Summarize attack attempts, detection categories, false positives, false negatives, and recommendations.
