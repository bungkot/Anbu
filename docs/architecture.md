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

## 3. Component diagram

```text
┌──────────────────────────────────────────────────────────────────┐
│ CLI (src/index.ts)                                                │
│   doctor | recon | pentest | report                              │
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
│  http.ts  crawl.ts  auth.ts  evidence.ts  checks/                 │
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
├── audit/
│   └── log.ts               # append-only hash-chained audit log
├── agent/
│   ├── loop.ts              # state machine and budget enforcement
│   ├── context.ts           # run context, memory, tool results
│   ├── planner.ts           # LLM planning and check selection
│   └── prompts.ts           # prompt templates (system/user)
├── tools/
│   ├── http.ts              # guarded HTTP client
│   ├── crawl.ts             # link/form/endpoint discovery
│   ├── auth.ts              # session and credential handling
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
│   ├── markdown.ts
│   ├── json.ts
│   └── sarif.ts
└── store/
    └── evidence-store.ts
```

## 5. Data model

### Scope
- `version`, `authorization` (reference, owner, expiry, signature/token).
- `targets[]`: scheme, host, port, path prefix, allowed HTTP methods.
- `deny[]`: hosts, IP ranges, paths that must never be touched.
- `policy`: rate limits, max body size, max requests, read-only flag,
  state-changing allowlist, destructive deny list.
- `testClasses[]`: OWASP categories in scope.

### Finding
- `id`, `category` (A01-A10), `cwe`, `severity`, `confidence`.
- `title`, `affected` (URL, parameter, endpoint).
- `evidence[]`: request, response metadata, sanitized bodies, timestamp.
- `reproduction`: exact steps.
- `remediation`: mapped to OWASP prevention guidance.
- `falsePositiveAnalysis`: why the finding is not a false positive.

### Evidence
- Stored under a run directory with a content hash.
- Raw artifacts are never rendered directly into the LLM context without
  sanitization and size limits.

## 6. LLM integration

- The OpenCode SDK hosts a local OpenCode server; the Ollama provider is passed
  inline (see `src/opencode.ts`).
- The LLM receives a **structured task prompt**: attack surface summary,
  selected OWASP checks, tool schemas, and budget. It returns structured JSON.
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
4. **Policy check** — body size, content type, redirect behavior, and
   destructive-action rules.
5. **Rate limit** — per-host token bucket plus a global request budget.

A violation is recorded in the audit log and the request is dropped. The loop
can be configured to halt on repeated violations.

## 8. Concurrency and budget

- Requests are issued with bounded concurrency per host (default 1-2).
- The loop enforces: max requests, max wall-clock time, max LLM turns, and max
  findings per category.
- Budgets are part of the scope document and are reported at the end of a run.

## 9. Extensibility

- A check implements a common interface: metadata (category, CWE, read-only),
  `run(context)`, and a list of candidate findings.
- Checks are registered in `src/tools/checks/index.ts`.
- LLM-guided probes use the same tool layer and produce the same finding shape.

## 10. Deployment

- **Host**: Node + Ollama in Docker; run the `pentest` CLI (planned; see `ROADMAP.md`).
- **Container**: `docker compose run --rm --entrypoint node app /app/dist/index.js pentest --scope ...` (planned; see `ROADMAP.md`).
- **Dev container**: open the folder in VS Code and use "Reopen in Container";
  the repository is mounted at `/workspace`.
- Ollama is bound to `127.0.0.1` only; no target data leaves the machine.
