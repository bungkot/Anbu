---
name: A10 Mishandling of Exceptional Conditions
description: Test and report OWASP A10 Mishandling of Exceptional Conditions. Use when implementing or reviewing fail-open behavior, sensitive errors, parameter handling, resource exhaustion, race conditions, or transaction-integrity checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A10) and `docs/tool-reference.md`.

## Checks

- **Fail open** — errors, missing parameters, or insufficient privileges that
  grant access instead of denying it.
- **Sensitive errors** — stack traces, SQL errors, paths, versions disclosed.
- **Missing parameter handling** — omitted/extra parameters causing unexpected
  behavior.
- **Resource exhaustion** — uploads, loops, or large payloads leaking
  resources.
- **Race conditions** — bounded, non-destructive concurrency probes on safe
  operations.
- **Transaction integrity** — interrupted multi-step flows that skip rollback.

## Rules

- Use safe error triggers; never crash the target.
- Keep concurrency probes small and rate-limited.
- Do not attempt to exploit a race condition for impact; detect and report.
- Report impact estimates, not speculation.

## False-positive control

- Confirm the error is reachable by an unauthenticated/low-privilege user
  where relevant.
- Distinguish verbose error detail from a directly exploitable flaw.
- Reproduce resource issues with a controlled, bounded request.
