# Tool reference

Tools are the only way the agent loop can interact with a target. Every tool
call is validated by the guardrail layer before execution. The planner sees a
closed schema and cannot invent tools or bypass arguments.

> Status: `http_request`, `crawl`, `capture_evidence`, `compare_evidence`, and
> `parse_response` are implemented in `src/tools/` and `src/store/` (M2) and are
> exercised by `npm run recon` and the unit suite. The closed agent-facing
> schemas and the remaining tools arrive with M3/M4; see `ROADMAP.md`.

## Common result shape

```json
{
  "ok": true,
  "evidenceId": "sha256:...",
  "summary": "HTTP 200, 12 KiB, application/json",
  "data": {}
}
```

On failure, `ok` is `false`, `error` is a safe message, and no request is
reported as sent if a guardrail blocked it.

## Network and discovery

### `http_request`
Send a single HTTP request.
- Arguments: `method`, `url`, `headers`, `body`, `followRedirects`.
- Guardrails: scope, deny, authorization, method policy, body size, rate limit.
- Returns: status, headers, body excerpt, timing, evidence reference.
- Notes: redirects are re-checked against scope; external redirects are not
  followed by default.

### `crawl`
Discover links, forms, and static assets from an allowed URL.
- Arguments: `url`, `maxDepth`, `maxUrls`.
- Returns: discovered URLs, forms (method, action, parameters), technologies.
- Notes: stays within scope; honors `maxRequests`.

### `discover_endpoints`
Enumerate likely API and admin endpoints from a wordlist and fuzzing rules.
- Arguments: `baseUrl`, `wordlist`, `methods`.
- Notes: only GET/HEAD unless state-changing is approved.

### `parse_response`
Extract structured facts from a captured response (headers, cookies, forms,
links, framework markers).
- Arguments: `evidenceId`.
- Notes: operates on stored evidence; does not make network calls.

## Session and authentication

### `auth_login`
Establish a session using configured test credentials.
- Arguments: `flow`, `usernameEnv`, `passwordEnv`.
- Notes: credentials come from the environment; never from the model. Sessions
  are scoped to the run and redacted from output.

### `auth_logout`
Invalidate the current session and verify invalidation.

### `session_replay`
Repeat an authenticated request with a different user context to test access
  control (A01/A07).
- Notes: requires an explicit scope entry and test accounts.

## Evidence

### `capture_evidence`
Store a request/response artifact with sanitization and a content hash.
- Arguments: `request`, `response`, `redact`.
- Returns: `evidenceId`, `path`, `sha256`.

### `compare_evidence`
Compare a candidate response against a baseline artifact.
- Arguments: `candidateEvidenceId`, `baselineEvidenceId`.
- Returns: status/headers/body differences.

## Deterministic checks

Each check is a tool with a closed input and a list of candidate findings.

| Tool | OWASP | What it does |
|---|---|---|
| `check_security_headers` | A02 | Inspects HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, cookies. |
| `check_tls` | A04 | Checks TLS version, cipher strength, certificate chain, HSTS. |
| `check_password_hash` | A04 | Inspects exposed password policy/hashing hints and known weak formats. |
| `check_sqli` | A05 | Sends parameterized, non-destructive SQL probes and analyzes errors/timing. |
| `check_xss` | A05 | Tests reflection in HTML, attributes, JavaScript, and DOM sinks. |
| `check_command_injection` | A05 | Tests command separators on input reflected into command contexts. |
| `check_xxe` | A05 | Tests XML parsers with safe external-entity probes. |
| `check_path_traversal` | A01/A05 | Tests file/path parameters with traversal sequences. |
| `check_idor` | A01 | Replays object access with alternate IDs/roles. |
| `check_force_browsing` | A01 | Requests privileged URLs unauthenticated and as a low-privilege user. |
| `check_cors` | A01 | Tests CORS policy with unauthorized origins. |
| `check_jwt` | A01/A07 | Tests algorithm confusion, signature bypass, expiry, and audience claims. |
| `check_authz_methods` | A01 | Checks POST/PUT/DELETE authorization on API endpoints. |
| `check_default_credentials` | A02/A07 | Tests documented default credentials on test accounts only. |
| `check_error_handling` | A10 | Forces safe error conditions and inspects messages for sensitive data. |
| `check_logging` | A09 | Verifies that test login/access events are logged and alertable. |
| `check_dependencies` | A03 | Scans the project's dependency graph against known advisories. |
| `check_deserialization` | A08 | Detects insecure deserialization markers and gadget surface. |
| `check_upload` | A06 | Tests unrestricted upload with harmless, non-executable payloads. |
| `check_rate_limit` | A06/A10 | Sends a bounded burst and observes throttling behavior. |

Check inputs and outputs are versioned. Checks declare whether they are
read-only or state-changing; state-changing checks require approval.

## Model-guided tools

### `propose_probe`
Ask the planner for the next highest-value probe given the current context.
- Returns: structured probe plan, never raw shell commands.

### `explain_finding`
Ask the planner to explain a candidate finding and suggest reproduction steps.
- Notes: the explanation is advisory; verification is deterministic.

## Prohibited capabilities

The tool layer must never expose:
- Arbitrary shell execution based on model output.
- Arbitrary file write outside the evidence store.
- Direct network access that bypasses the guardrail layer.
- Reading or exporting credentials/tokens into the model context.
