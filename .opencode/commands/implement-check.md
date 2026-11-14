---
description: Implement an OWASP check or tool with guardrails, evidence, and tests.
agent: pentester
---

Implement $ARGUMENTS.

Load the matching skill (`a01-broken-access-control`,
`a02-security-misconfiguration`, `a03-software-supply-chain-failures`,
`a04-cryptographic-failures`, `a05-injection`, `a06-insecure-design`,
`a07-authentication-failures`, `a08-software-or-data-integrity-failures`,
`a09-security-logging-and-alerting-failures`,
`a10-mishandling-of-exceptional-conditions`, `owasp-top10-2025`, or
`recon-and-scope`) and read the relevant docs. Follow
`docs/architecture.md`, `docs/agentic-loop.md`, and `docs/tool-reference.md`.
Add deterministic logic, guardrail enforcement, evidence capture, and unit
tests. Run `npm run typecheck` and `npm run build` when the implementation is
complete.
