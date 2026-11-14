# Scope and authorization

## 1. Why this exists

Web application testing can easily cross legal and ethical lines. Anbu is
built so that a run cannot start, and a request cannot be sent, unless the
target is covered by an explicit authorization and scope.

**Rules of engagement**

- Test only assets you own or have written permission to test.
- Keep the scope as small as possible.
- Respect rate limits and stop conditions.
- Do not exfiltrate data; evidence stays in the local evidence store.
- Report findings responsibly to the asset owner.

## 2. Scope document

The scope document is JSON. It is the single source of truth for what may be
tested and how.

```json
{
  "version": 1,
  "name": "Example authorized assessment",
  "authorization": {
    "reference": "PENTEST-2026-001",
    "owner": "Example Corp security team",
    "issuedBy": "CISO Office",
    "validFrom": "2026-01-01T00:00:00Z",
    "validUntil": "2026-12-31T23:59:59Z",
    "token": "env:ANBU_AUTH_TOKEN"
  },
  "targets": [
    {
      "host": "test.example.com",
      "scheme": "https",
      "port": 443,
      "paths": ["/app", "/api"],
      "methods": ["GET", "HEAD", "OPTIONS", "POST"]
    }
  ],
  "deny": [
    { "host": "*.example.com", "paths": ["/admin/delete", "/internal"] },
    { "cidr": "10.0.0.0/8" }
  ],
  "testClasses": ["A01", "A02", "A04", "A05", "A07", "A10"],
  "readOnly": false,
  "stateChanging": {
    "mode": "approve",
    "allow": ["POST /api/contact"]
  },
  "policy": {
    "maxRequests": 800,
    "maxDurationMinutes": 60,
    "maxConcurrentPerHost": 2,
    "requestsPerSecondPerHost": 5,
    "maxBodyBytes": 65536,
    "maxRedirects": 3,
    "followExternalRedirects": false
  }
}
```

### Field rules

- `authorization.token` may reference an environment variable. The token is
  never written to evidence or logs.
- `targets` is an allowlist. Anything not listed is out of scope.
- `deny` wins over `targets`.
- `testClasses` limits which OWASP categories run. Omitted categories are
  reported as `not_applicable`.
- `readOnly: true` blocks all state-changing methods regardless of other
  fields.
- `stateChanging.mode` is `deny` (default), `approve` (human gate), or `allow`
  (only for explicitly listed endpoints).

## 3. Authorization validation

At `intake`, the engine checks:

1. The scope document parses and has a supported `version`.
2. `authorization` is present with `reference`, `owner`, `validFrom`,
   `validUntil`.
3. The current time is within the validity window.
4. The token resolves and is non-empty.
5. At least one target is present and non-empty.

If any check fails, the engine refuses to start and prints the reason. It never
falls back to a default scope.

## 4. Request guardrails

Every outbound request passes through this order:

1. **Scope allowlist** — scheme, host, port, and path prefix must match a
   target.
2. **Deny list** — host/path/CIDR denials are checked and always win.
3. **Authorization** — the authorization document is still valid.
4. **Policy** — method, body size, content type, redirect behavior.
5. **Rate limit** — per-host token bucket and global request budget.
6. **Audit** — the decision and request metadata are logged.

A blocked request is never sent. The loop records the violation and may halt if
violations repeat.

## 5. Redirect and SSRF controls

- Redirects are followed only within the scope allowlist.
- External redirects are not followed by default.
- Redirect chains are capped by `maxRedirects`.
- URL parameters that influence outbound requests (for example `?url=`) are
  treated as untrusted and are never fetched unless the resulting URL is in
  scope. This is the primary SSRF containment control.

## 6. Credentials and sessions

- Test credentials are supplied through environment variables or a secrets
  file, never hardcoded and never committed.
- Sessions are scoped to the run and discarded at the end.
- Credentials are redacted from evidence and logs.
- Credential-stuffing and brute-force checks require explicit test accounts
  and an explicit scope entry; they are denied by default.

## 7. Evidence handling

- Evidence is written to a run directory outside the repository by default.
- Raw artifacts are hashed; only sanitized excerpts enter the LLM context.
- Personal data, tokens, cookies, and credentials are redacted.
- Evidence retention is configured and reported; it is the operator's
  responsibility to store it securely.

## 8. Audit log

The audit log records, at minimum:

- Run ID, scope reference, and operator.
- Every guardrail decision (allow/deny) with reason.
- Every state-changing request and its approval.
- Budget consumption and stop reason.

The audit log is tamper-evident (append-only) and is shipped with the report.

## 9. Intake command

Validate a scope document and its authorization before a run:

```bash
npm run intake -- --scope scope/example.json
```

`ANBU_SCOPE_FILE` is used when `--scope` is omitted. On success the command
prints the accepted targets, test classes, read-only flag, and authorization
reference. On failure it prints one bullet per reason and exits with code 1.
It performs no network I/O.
