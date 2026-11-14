---
name: A09 Security Logging and Alerting Failures
description: Test and report OWASP A09 Security Logging and Alerting Failures. Use when implementing or reviewing audit coverage, sensitive-data-in-logs, log injection, log integrity, or alerting checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A09) and `docs/tool-reference.md`.

## Checks

- **Audit coverage** — logins, failed logins, access-control failures, and
  high-value transactions are logged.
- **Sensitive data in logs** — PII, credentials, tokens in log output.
- **Log injection** — CRLF/format-string probes into log-controlled inputs.
- **Log integrity** — tamper-evident or append-only storage.
- **Alerting** — suspicious activity triggers an alert; no alert fatigue.

## Rules

- Generate test events with test accounts only.
- Use safe log-injection payloads; do not disrupt logging.
- Do not attempt to read or tamper with production logs.

## False-positive control

- Confirm the event is reachable by the tested user and actually missing.
- Distinguish a logging gap from an alerting-pipeline gap.
- Report the compliance/forensics impact, not just the absence of a log.
