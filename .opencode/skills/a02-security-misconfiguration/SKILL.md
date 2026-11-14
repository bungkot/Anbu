---
name: A02 Security Misconfiguration
description: Test and report OWASP A02 Security Misconfiguration. Use when implementing or reviewing hardening, default credentials, directory listing, error handling, security headers, cookie flags, cloud permissions, or XXE checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A02) and `docs/tool-reference.md`.

## Checks

- **Hardening** — unnecessary ports, services, pages, accounts, samples,
  testing frameworks.
- **Default credentials** — default accounts still enabled (test accounts only).
- **Directory listing** — exposed directories and backup/metadata files.
- **Error messages** — stack traces and verbose errors to users.
- **Security headers** — HSTS, CSP, X-Frame-Options, Referrer-Policy,
  Permissions-Policy, X-Content-Type-Options.
- **Cookies** — Secure, HttpOnly, SameSite.
- **Cloud permissions** — publicly accessible storage buckets (only if in
  scope and authorized).
- **XXE / entity expansion** — XML parser configuration.

## Rules

- Prefer pass/fail checks with clear evidence.
- Do not fetch external resources during probes.
- Do not store sensitive data from the target.
- Report missing headers as Medium/Low unless combined with a concrete
  exploitable flow.

## False-positive control

- Distinguish "missing header" from "vulnerability"; report the impact.
- Check whether the resource is actually sensitive before reporting exposure.
- Re-run with a fresh connection to avoid cached or proxied responses.
