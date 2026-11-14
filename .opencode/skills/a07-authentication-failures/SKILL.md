---
name: A07 Authentication Failures
description: Test and report OWASP A07 Authentication Failures. Use when implementing or reviewing default/weak credentials, brute force, session management, recovery, MFA, or JWT checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A07) and `docs/tool-reference.md`.

## Checks

- **Default/weak credentials** — only on explicit test accounts.
- **Brute force / credential stuffing** — only with test accounts and an
  explicit scope entry; rate-limited.
- **Session management** — fixation, logout invalidation, idle/absolute
  timeout, session ID in URL.
- **Recovery flows** — account enumeration, weak knowledge-based recovery.
- **MFA** — missing or bypassable MFA on sensitive actions.
- **JWT** — algorithm confusion, signature bypass, claim validation.

## Rules

- Use test accounts; never real user credentials.
- Rate-limit every authentication probe; stop on lockout.
- State-changing auth tests require approval.
- Evidence must show the authentication boundary and the server's response.

## False-positive control

- Confirm the account is a test account and the behavior is not intended.
- Check whether lockout/throttling is configured before reporting brute force.
- Reproduce with a fresh session.
