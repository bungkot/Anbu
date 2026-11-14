---
name: A05 Injection
description: Test and report OWASP A05 Injection. Use when implementing or reviewing SQLi, XSS, OS command, LDAP, ORM, expression-language, SSTI, XXE, or CRLF checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A05) and `docs/tool-reference.md`.

## Checks

- **SQL injection** — parameterized, non-destructive probes; error, union, and
  boolean/time-based signals; compare against baseline.
- **XSS** — reflected in HTML, attributes, JavaScript, and DOM sinks; use
  harmless sentinel payloads; verify execution context, not just reflection.
- **OS command injection** — safe separators and benign commands only; never
  destructive commands.
- **LDAP / ORM / EL / OGNL** — context-appropriate escaping tests.
- **SSTI** — template expression probes; observe rendering differences.
- **XXE** — safe external entity probes; do not fetch external resources.
- **CRLF** — header injection probes; check response splitting.

## Rules

- Keep data separate from commands/queries; prefer safe APIs.
- Validate, filter, or sanitize only as defense-in-depth.
- Do not run destructive payloads to prove impact.
- Capture evidence for both the payload request and the baseline request.
- A finding requires a differential signal (response, error, timing, DOM) that
  the baseline does not explain.

## False-positive control

- Baseline-compare every candidate.
- Ignore generic WAF blocks unless they reveal the underlying sink.
- Require a second independent payload or a safe reproduction before reporting.
- Record the interpreter context (SQL dialect, template engine, shell) in the
  finding.
