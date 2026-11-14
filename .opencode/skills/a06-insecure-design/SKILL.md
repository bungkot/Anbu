---
name: A06 Insecure Design
description: Test and report OWASP A06 Insecure Design. Use when implementing or reviewing business-logic abuse, workflow bypass, rate-limit, trust-boundary, upload, or credential-storage design checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A06) and `docs/tool-reference.md`.

## Checks

- **Business-logic abuse** — price/quantity/role/coupon manipulation, workflow
  step skipping, replay of one-time actions.
- **Missing rate limits** — sensitive or expensive actions without throttling.
- **Trust-boundary violations** — client-side enforcement of authorization,
  pricing, or state transitions.
- **Unsafe workflow assumptions** — multi-step flows that accept out-of-order or
  repeated submissions.
- **Unrestricted upload** — missing type/size/content validation that enables
  dangerous files or resource abuse.
- **Credential storage design** — passwords or secrets stored or transmitted
  without adequate protection.
- **Excessive functionality** — debug/admin features enabled in production.

## Rules

- Design findings are model-guided; reason about intended behavior first.
- Do not exploit business logic for real impact (no real purchases, transfers,
  or account changes).
- Use test accounts and test data only.
- A design flaw needs evidence that the abuse path is reachable and the server
  accepts it.

## False-positive control

- Confirm the behavior contradicts the documented/intended business rule.
- Distinguish a missing convenience control from a real risk.
- Reproduce with a fresh test account and record the exact request sequence.
