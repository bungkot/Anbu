# Tool reference

Tools are the only way the agent loop can interact with a target. Every
network call goes through `GuardedHttpClient`, so scope, deny, authorization,
policy, rate limit, and audit are applied uniformly. The planner never calls a
tool directly: it returns a closed JSON plan, and the loop executes each action
through the tool layer.

> Status: the planner action schema, the guarded HTTP client, the crawler, the
> evidence tools, and the 20 deterministic checks below are implemented and
> covered by `test/unit`, `test/integration`, and `test/target`. See
> `ROADMAP.md` (M2-M5).

## Planner action schema

One planner turn returns exactly one JSON object:

```json
{
  "objective": "string",
  "actions": [
    { "kind": "run_check", "checkId": "sqli", "input": { "url": "https://target/app", "parameter": "id" } },
    { "kind": "http_request", "input": { "method": "GET", "url": "https://target/app" } },
    { "kind": "halt", "reason": "objective met" }
  ],
  "rationale": "string (optional)"
}
```

- `actions` is required; a plan may contain at most `maxActionsPerPlan`
  actions (default 10).
- `run_check.checkId` must be a registered check whose categories intersect the
  scope's `testClasses`.
- `http_request` is observation only; it does not create findings by itself.
- `halt` stops the planner loop and is recorded in the audit log.
- Unknown fields are ignored; malformed plans are rejected. Two consecutive
  planner failures disable the model for the rest of the run.

### `run_check`

Run one deterministic check.

- Arguments: `checkId` plus a closed `input` object: `url` (required),
  `method`, `headers`, `body`, `parameter`, `evidenceId`, `options`.
- Guardrails: the check's `fetch` goes through the guarded client, and each
  check has a hard per-run request cap (`maxRequests`).
- Returns `CheckResult`: `ok`, `findings`, `requests`, `evidence`, and an
  optional `error` or `skipped`.
- Approval: read-only checks run without a gate; state-changing checks call the
  configured approval provider before running.

### `http_request`

Send one guarded HTTP request and capture evidence.

- Arguments: `method`, `url`, `headers`, `body`.
- Redirects are resolved manually and every hop is re-checked against the
  scope. `followRedirects` is not an argument: redirect behavior comes from
  `policy.maxRedirects` and `policy.followExternalRedirects`.
- Returns: `ok`, `status`, `headers`, size-capped `bodyText`, `bodyBytes`,
  `truncated`, `durationMs`, `redirects`, and an `evidenceId` for successful
  requests.

### `halt`

Stop the run. Arguments: `reason`.

## Internal tools

These are used by the engine; they are not offered to the planner.

### `crawl`

Read-only BFS discovery used by `recon` and the pentest recon state.

- Arguments: `startUrl`, `maxDepth` (default 2), `maxUrls` (default 50),
  `stayInScope` (default true).
- Returns: `startUrl`, `ok`, `urls`, `forms` (method, action, parameters),
  `assets`, `technologies`, `blocked`, `requests`, `truncated`, `maxDepth`, and
  `maxUrls`.

### `capture_evidence`

Store a request/response artifact with redaction and a content hash.

- Arguments: `request`, `response`, `redact` (default true).
- Returns: `evidenceId`, `path`, `sha256`, `sizeBytes`.

### `compare_evidence`

Compare a candidate artifact with a baseline artifact.

- Arguments: `candidateEvidenceId`, `baselineEvidenceId`.

### `parse_response`

Extract headers, cookies, forms, links, assets, and technology markers from
stored evidence. Makes no network calls.

- Arguments: `evidenceId`.

## Deterministic checks

Each check declares its OWASP categories, CWE, default severity, per-run request
cap, and whether it is read-only. Read-only checks run in the deterministic
baseline and in planner plans; state-changing checks (`xxe`, `authz-methods`,
`default-credentials`, `upload`) require approval.

| Tool | id | OWASP | CWE | Gate | What it does |
|---|---|---|---|---|---|
| `check_security_headers` | `security-headers` | A02 | CWE-693 | read-only | Inspects HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options, and cookie flags. |
| `check_tls` | `tls` | A04 | CWE-326 | read-only | Checks TLS version, cipher strength, certificate validity, hostname match, key size, and HSTS for approved TLS observations. |
| `check_password_hash` | `password-hash` | A04 | CWE-916 | read-only | Inspects response bodies for weak password hash formats and cleartext password fields while ignoring strong KDF hashes. |
| `check_dependencies` | `dependencies` | A03 | CWE-1104 | read-only | Scans an npm lockfile or a supplied dependency list against a curated offline advisory snapshot. Issues no HTTP requests. |
| `check_sqli` | `sqli` | A05 | CWE-89 | read-only | Sends parameterized, non-destructive SQL probes and analyzes error messages and boolean differentials. |
| `check_xss` | `xss` | A05 | CWE-79 | read-only | Tests reflection in HTML, attribute, and script contexts with harmless markers and ignores encoded output. |
| `check_command_injection` | `command-injection` | A05 | CWE-78 | read-only | Tests command separators and substitution syntax on reflected input and requires a shell error signature. |
| `check_xxe` | `xxe` | A05 | CWE-611 | approval | Tests XML parsers with safe external-entity probes that reference a non-existent local file. |
| `check_path_traversal` | `path-traversal` | A01/A05 | CWE-22 | read-only | Tests file/path parameters with traversal sequences and detects protected file content in the response. |
| `check_idor` | `idor` | A01 | CWE-639 | read-only | Replays object access with alternate ids using the same session and compares the responses. |
| `check_force_browsing` | `force-browsing` | A01 | CWE-284 | read-only | Requests privileged URLs unauthenticated and detects administrative content in the response. |
| `check_cors` | `cors` | A01 | CWE-942 | read-only | Tests CORS with unauthorized origins and detects credentialed or arbitrary-origin responses. |
| `check_jwt` | `jwt` | A01/A07 | CWE-347 | read-only | Tests algorithm confusion, the `none` algorithm, signature presence, expiry, and audience claims. |
| `check_authz_methods` | `authz-methods` | A01 | CWE-862 | approval | Checks POST/PUT/DELETE authorization on API endpoints and reports requests that reach the handler unauthenticated. |
| `check_default_credentials` | `default-credentials` | A02/A07 | CWE-798 | approval | Tests documented default credentials on test accounts only and reports successful authentication. |
| `check_error_handling` | `error-handling` | A10 | CWE-209 | read-only | Forces safe error conditions and inspects messages for stack traces, paths, and framework debug data. |
| `check_logging` | `logging` | A09 | CWE-778 | read-only | Verifies that test login/access events are logged and alertable, and detects anonymously exposed audit logs. |
| `check_deserialization` | `deserialization` | A08 | CWE-502 | read-only | Detects Java, .NET, PHP, and Python serialization markers and gadget surface in responses. |
| `check_upload` | `upload` | A06 | CWE-434 | approval | Tests unrestricted upload with harmless, non-executable HTML payloads and verifies whether the stored file is served. |
| `check_rate_limit` | `rate-limit` | A06/A10 | CWE-770 | read-only | Sends a bounded burst of read-only requests and observes throttling behavior. |

### Check options

Checks accept a closed `options` object. Unknown option keys are ignored.

| Check | Options |
|---|---|
| `sqli`, `xss`, `command-injection`, `path-traversal`, `error-handling` | `parameter` (string) |
| `idor` | `parameter` (string), `alternates` (string array of alternate ids) |
| `jwt` | `token` (JWT string to analyze) |
| `deserialization` | `body` (serialized payload to analyze) |
| `tls` | `tls` (record describing an observed TLS connection) |
| `force-browsing`, `logging` | `paths` or `endpoints` (string array of candidate paths) |
| `authz-methods` | `methods` or `verbs` (string array of HTTP methods) |
| `rate-limit` | `requests` (number of burst requests) |
| `default-credentials` | `credentials` (username/password pairs), `usernameField`, `passwordField` |
| `dependencies` | `dependencies` (dependency list), `projectDir` (lockfile directory) |
| `upload` | `fieldName`, `filename`, `contentType`, `content`, `marker` |

Check inputs and outputs are versioned together with the check implementation.
The registry invariants are validated by `validateCheckRegistry()` and exercised
in `test/unit/checks/registry.test.ts`.

## Prohibited capabilities

The tool layer must never expose:

- Arbitrary shell execution based on model output.
- Arbitrary file write outside the evidence store.
- Direct network access that bypasses the guardrail layer.
- Reading or exporting credentials/tokens into the model context.
- A planner action kind outside `run_check`, `http_request`, and `halt`.
