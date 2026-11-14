---
name: A01 Broken Access Control
description: Test and report OWASP A01 Broken Access Control. Use when implementing or reviewing IDOR/BOLA, authorization, privilege escalation, CORS, path traversal, open redirect, CSRF, or SSRF checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A01) and `docs/tool-reference.md`.

## Checks

- **IDOR/BOLA** — replay object access with alternate IDs and roles; verify
  server-side authorization.
- **Force browsing** — request privileged URLs unauthenticated and as a
  low-privilege user.
- **Method authorization** — test POST/PUT/DELETE on APIs with missing checks.
- **Privilege escalation** — role/cookie/JWT tampering; validate signature,
  issuer, audience, expiry.
- **CORS** — unauthorized origins; credentials + permissive origin reflection.
- **Path traversal** — file/path parameters with traversal sequences.
- **Open redirect** — unvalidated redirect targets (CWE-601).
- **CSRF** — state-changing requests without anti-CSRF protection.
- **SSRF** — URL-fetching parameters resolving to internal hosts (CWE-918);
  re-check every redirect against scope.

## Rules

- Deny by default; access control must be enforced server-side.
- Use test accounts; never real user credentials.
- State-changing auth tests require approval.
- Evidence must show both the unauthorized request and the server's response.

## False-positive control

- Confirm the object belongs to another user/tenant.
- Confirm the behavior is not an intentional public endpoint.
- Reproduce with a second account or a fresh session.
