# Architecture

## 1. Purpose

Anbu is an authorized web application security testing engine. It runs a
bounded agentic loop that combines deterministic, auditable checks with
LLM-guided planning and analysis. Findings are mapped to the OWASP Top
10:2025.

The architecture prioritizes four properties:

1. **Authorization** — no request leaves the process unless the target is in a
   valid scope.
2. **Reproducibility** — every finding links to captured request/response
   evidence.
3. **Low false positives** — candidate findings must be reproduced and
   validated before they are reported.
4. **Containment** — target content is untrusted data; it can never become
   instructions or shell commands.

## 2. Design goals and non-goals

**Goals**
- Scope enforcement at the network-client boundary, not as an afterthought.
- Deterministic checks for high-signal patterns; LLM reasoning for planning,
  fuzzing guidance, and report writing.
- Offline-capable operation through Ollama; no target data sent to a cloud
  provider by default.
- Extensible check registry keyed by OWASP category and CWE.
- Machine-readable output (JSON, SARIF) and human-readable output (Markdown).

**Non-goals**
- Mass exploitation, credential cracking at scale, or evasion of detection.
- Testing systems without explicit permission.
- Replacing manual review; the report is an input to a human process.
- Shipping a target application; the engine tests systems you provide and
  authorize.

## 3. Component diagram

```text
┌──────────────────────────────────────────────────────────────────┐
│ CLI (src/index.ts)                                               │
│   doctor | ask | intake | recon | pentest | report               │
└───────────────┬──────────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────────┐
│ Agentic loop (src/agent/loop.ts)                                  │
│  intake → recon → plan → execute → verify → report → halt         │
│   │       │       │        │         │        │                   │
│   │       │       │        │         │        │                   │
│  ┌▼──────────────────────────────────────────────────────────┐  │
│  │ LLM planner (src/agent/planner.ts + src/opencode.ts)        │  │
│  │  OpenCode SDK → Ollama (local)                              │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────┬──────────────────────────────────────────────────┘
                │ tool calls (structured JSON)
┌───────────────▼──────────────────────────────────────────────────┐
│ Tool layer (src/tools/)                                           │
│  http.ts  crawl.ts  evidence.ts  checks/                          │
└───────────────┬──────────────────────────────────────────────────┘
                │ every call passes through
┌───────────────▼──────────────────────────────────────────────────┐
│ Guardrails (src/guardrails/)                                      │
│  scope.ts  authorization.ts  policy.ts  rate-limit.ts             │
└───────────────┬──────────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────────┐
│ Evidence store (src/store/)  │  Report (src/report/)              │
│  raw + sanitized artifacts   │  markdown / json / sarif            │
└──────────────────────────────────────────────────────────────────┘
```

## 4. Module layout

```text
src/
├── index.ts                 # CLI entry point
├── config.ts                # env-based configuration (single source)
├── health.ts                # Ollama readiness + model checks
├── opencode.ts              # OpenCode SDK server/client + Ollama provider
├── intake.ts                # scope loading and intake validation
├── recon.ts                 # read-only crawl + attack-surface aggregation
├── pentest.ts               # pentest CLI command
├── report.ts                # report CLI command
├── audit/
│   └── log.ts               # append-only hash-chained audit log
├── agent/
│   ├── loop.ts              # state machine and budget enforcement
│   ├── context.ts           # run context, memory, tool results
│   ├── planner.ts           # LLM planning and check selection
│   ├── prompts.ts           # prompt templates (system/user)
│   ├── budget.ts            # budget resolution and stop reasons
│   ├── approval.ts          # human-in-the-loop approval providers
│   └── verify.ts            # reproduction and false-positive suppression
├── tools/
│   ├── http.ts              # guarded HTTP client
│   ├── crawl.ts             # link/form/endpoint discovery
│   ├── evidence.ts          # request/response capture and sanitization
│   └── checks/              # deterministic OWASP checks, one file per area
├── guardrails/
│   ├── scope.ts             # allowlist/denylist enforcement
│   ├── authorization.ts     # authorization document validation
│   ├── policy.ts            # method, body-size, destructive-action policy
│   └── rate-limit.ts        # per-host and global request budgets
├── model/
│   ├── scope.ts             # Scope, Target, Authorization
│   ├── finding.ts           # Finding, Evidence, Severity, Confidence
│   └── report.ts            # Report and Coverage types
├── report/
│   ├── index.ts             # shared exports
│   ├── shared.ts            # finding selection and formatting helpers
│   ├── markdown.ts
│   ├── json.ts
│   └── sarif.ts
└── store/
    └── evidence-store.ts
```

## 5. Data model

### Scope
- `version`, `name`, `authorization` (reference, owner, optional `issuedBy`,
  `validFrom`, `validUntil`, `token`).
- `targets[]`: host, optional `scheme`/`port`, path prefixes, allowed HTTP
  methods. Omitted `paths` means all paths; omitted `methods` means read-only
  methods.
- `deny[]`: host entries with optional path prefixes, or CIDR entries, that
  must never be touched. Deny wins over allow.
- `readOnly`: blocks all state-changing methods when true (default true).
- `stateChanging`: `deny` (default), `approve`, or `allow` with an explicit
  `METHOD /path` allowlist.
- `policy`: `maxRequests`, `maxDurationMinutes`, `maxConcurrentPerHost`
  (accepted but not enforced; requests are sequential),
  `requestsPerSecondPerHost`, `rateLimitWaitMs` (per-host pacing bound),
  `maxBodyBytes`, `maxRedirects`, `followExternalRedirects`, `maxModelTurns`,
  `maxFindingsPerCategory`.
- `testClasses[]`: OWASP categories in scope; defaults to all ten when omitted.

### Finding
- `id`, `category` (A01-A10), `cwe`, `severity`, `confidence`.
- `title`, `affected` (URL, parameter, endpoint).
- `evidence[]`: content-addressed references (`evidenceId`, `sha256`, path) to
  stored request/response artifacts.
- `reproduction`: exact steps.
- `remediation`: mapped to OWASP prevention guidance.
- `falsePositiveAnalysis`: why the finding is not a false positive.
- `verification`: result of the verify state (`status`, `reason`, `attempted`,
  optional reproduction `evidenceId`).

### Evidence
- Stored under a run directory with a content hash.
- Raw artifacts are never rendered directly into the LLM context without
  sanitization and size limits.

### Report
- Envelope: `reportVersion`, `runId`, `scopeReference`, `generatedAt`,
  `methodology`, `findings`, `coverage`, `budgets`, `stopReason`, `audit`.
- Written as `report.json`; rendered as `report.md` and `report.sarif`.
- Coverage statuses are `covered`, `not_applicable`, and `not_run`.
- Budgets report request, wall-clock, and model-turn usage against their limits.
- Only `confirmed` and `probable` findings appear in Markdown and SARIF by
  default; `report.json` keeps discarded candidates for audit.

## 6. LLM integration

- The OpenCode SDK hosts a local OpenCode server; the Ollama provider is passed
  inline (see `src/opencode.ts`).
- The LLM receives a **structured task prompt**: run metadata, the attack
  surface, the available read-only checks, the closed action schema, recent
  tool results, and the remaining budget. It returns structured JSON.
- The LLM never receives raw target responses larger than a configured cap and
  never receives secrets.
- LLM output is parsed strictly; unknown fields are discarded. Any tool call is
  re-validated by the guardrail layer before execution.
- Deterministic checks do not depend on the LLM, so the engine remains useful
  when the model is unavailable.

## 7. Guardrail layer

Every outbound request passes through:

1. **Scope check** — host, port, path, and method must be allowed.
2. **Deny check** — explicit deny entries win over allow entries.
3. **Authorization check** — the authorization document is valid and unexpired.
4. **Policy check** — body size, state-changing rules, and redirect behavior.
5. **Rate limit** — per-host token bucket plus a global request budget. When
   pacing is enabled the guardrail waits for a token (bounded by
   `rateLimitWaitMs`) and records the wait in the audit entry as `waitedMs`.

A violation is recorded in the audit log and the request is dropped. The loop
can be configured to halt on repeated violations.

## 8. Concurrency and budget

- Requests are issued sequentially. `policy.maxConcurrentPerHost` is accepted
  for forward compatibility but is not enforced.
- The loop enforces: max requests, max wall-clock time, max LLM turns, and max
  findings per category.
- Budgets are part of the scope document and are reported at the end of a run.

## 9. Extensibility

- A check implements a common interface: metadata (id, tool name, categories,
  CWEs, read-only/approval gate, severity, per-run request cap, references),
  `run(context)`, and a list of candidate findings.
- Checks are registered in `src/tools/checks/index.ts`.
- LLM-guided probes use the same tool layer and produce the same finding shape.

## 10. Deployment

- **Host**: Node + Ollama in Docker; run the `pentest` CLI.
- **Container**: `docker compose run --rm --entrypoint node app /app/dist/index.js pentest --scope ...`
- **Dev container**: open the folder in VS Code and use "Reopen in Container";
  the repository is mounted at `/workspace`.
- Ollama is bound to `127.0.0.1` only; no target data leaves the machine.

## 11. Targets and runtime servers

Anbu is the testing engine, not the target. The repository ships no target web
application. Three kinds of server appear around the engine, with different
roles:

| Server | Where | Role |
|---|---|---|
| Target application | Outside the repository | The system under test; for example OWASP Juice Shop started with `docker run`. |
| Ollama | `docker-compose.yml` (`ollama` service) | Local LLM inference for the planner, bound to `127.0.0.1:11434`. |
| Test fixtures | `test/target/fixture.ts`, `test/integration/helpers.ts` | Deliberately vulnerable HTTP servers bound to `127.0.0.1` on an ephemeral port, started only by the test suites. |

The `app` service in `docker-compose.yml` is a development container, not a web
server: it holds the repository open for `exec` and publishes no ports. The
embedded OpenCode SDK server in `src/opencode.ts` is transport to Ollama, not a
target. Anbu exposes no web UI or public API; all interaction is through the
CLI.

Targets are declared in scope files (`host`, `scheme`, `port`, `paths`,
`methods`). For example, `scope/juice-shop.local.json` points at
`localhost:3000`. The scope grants permission and bounds the run; it does not
provide the application. To exercise the engine, start a vulnerable
application you own (Juice Shop, WebGoat, DVWA, crAPI) and point a scope at it;
see [`verification.md`](verification.md) and
[`ci-ollama-smoke.md`](ci-ollama-smoke.md).

The test fixtures are deterministic and intentionally vulnerable (reflected XSS,
SQL error disclosure, permissive CORS, an unauthenticated admin page, and a
readable audit log) so check baselines stay reproducible. They never listen on
a public interface and are not part of the product.
