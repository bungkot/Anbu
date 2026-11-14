# Roadmap

This roadmap tracks Anbu from its current scaffolding to a usable, authorized
agentic pentester. Phases are sequential and each ends with a working,
verifiable increment. Guardrails and documentation are not deferred to the end:
they are part of every phase.

Status legend: `[x]` done · `[~]` in progress · `[ ]` planned

## Phase summary

| Phase | Goal | Key deliverables | Exit criteria |
|---|---|---|---|
| M0 | Scaffolding | Docker/Ollama, `doctor`, `ask`, docs, agents/skills | Repo builds; local model works |
| M1 | Foundation | Scope model, guardrails, audit log | Out-of-scope requests blocked before send |
| M2 | Tool layer | Guarded HTTP, crawl, evidence store | Every request guarded; evidence hashed/redacted |
| M3 | Deterministic checks | Checks for A01–A10 + fixtures | Vulnerable fixtures detected, safe ones ignored |
| M4 | Agentic loop | Loop, planner, budgets, HITL gates | `pentest` CLI runs end to end |
| M5 | Verification & reporting | Reproduction, coverage, Markdown/JSON/SARIF | Only confirmed/probable findings reported |
| M6 | End-to-end validation | Fixture baselines, CI, SBOM | Guardrail tests and baselines pass |
| M7 | v1.0 release | Docs match implementation | All release gates pass |

## M0 — Scaffolding

- [x] Repository, TypeScript ESM strict build, Docker Compose (Ollama + app/dev).
- [x] `src/config.ts`, `src/health.ts`, `src/opencode.ts`, `src/index.ts` with
      `doctor` and `ask`.
- [x] Local Ollama model pinning (`granite3.3:2b`) and dev container setup.
- [x] OWASP Top 10:2025 docs, agents, skills, and commands under `.opencode/`.
- [x] Scope document example and authorization rules documented.

Not yet implemented: the pentest CLI, agentic loop, tool layer, guardrails,
checks, evidence store, and reports.

## M1 — Foundation: config, scope, guardrails, audit

Goal: the engine can validate a scope and refuse anything out of scope before a
request exists.

Deliverables:

- [x] `src/model/scope.ts`, `src/model/finding.ts`, `src/model/report.ts`.
- [x] `src/guardrails/scope.ts`, `authorization.ts`, `policy.ts`, `rate-limit.ts`.
- [x] `src/config.ts` reads the `ANBU_*` variables documented in `.env.example`.
- [x] `src/audit/log.ts`: append-only, hash-chained audit log.
- [x] `src/intake.ts` and the `intake` CLI: validation with clear refusal reasons.
- [x] Unit tests under `test/unit` (`npm run test`).

Exit criteria:

- [x] Unit tests prove out-of-scope, denied, and expired-authorization requests are
  blocked before any network call.
- [x] `npm run doctor` still passes; typecheck and build are clean.

Status: complete. 41 unit tests pass; `npm run typecheck` and `npm run build`
are clean.

## M2 — Tool layer and evidence (in progress)

Goal: a guarded HTTP client and a local evidence store.

Deliverables:

- [x] `src/tools/http.ts` — guarded HTTP client. Every request and redirect
      hop passes scope → deny → authorization → policy → rate limit → audit;
      external redirects are not followed by default; response bodies are
      size-capped.
- [x] `src/tools/crawl.ts` — read-only, BFS link/form/asset/technology
      discovery through the guarded client; honors `maxDepth`, `maxUrls`, the
      request budget, deny rules, and `<base href>` resolution.
- [ ] `src/tools/evidence.ts`.
- [ ] `src/store/evidence-store.ts` with hashing, size caps, and redaction.
- [ ] `capture_evidence`, `compare_evidence`, and `parse_response` tools.
- [ ] `recon` CLI command (read-only crawl and attack-surface summary).

Exit criteria:

- Every outbound request passes scope → deny → authorization → policy → rate
  limit → audit.
- Evidence artifacts are hashed and redacted; no secrets in logs or prompts.

## M3 — Deterministic checks (A01–A10)

Goal: high-signal checks that do not depend on the LLM.

Deliverables:

- `src/tools/checks/` with one file per area, registered in `index.ts`.
- Checks from `docs/tool-reference.md`: security headers, TLS, password hash,
  SQLi, XSS, command injection, XXE, path traversal, IDOR, force browsing, CORS,
  JWT, authorization methods, default credentials, error handling, logging,
  dependencies, deserialization, upload, and rate limit.
- Unit fixtures: a vulnerable and a safe variant per check.

Exit criteria:

- Each check detects its vulnerable fixture and ignores the safe one.
- False-positive rate below 10% on the fixture suite.
- Checks declare read-only vs state-changing; state-changing checks require
  approval.

## M4 — Agentic loop and planner

Goal: the bounded loop that plans, executes, verifies, and halts.

Deliverables:

- `src/agent/loop.ts`, `context.ts`, `planner.ts`, `prompts.ts`.
- LLM planner via the OpenCode SDK with a closed tool schema and structured JSON.
- Budgets: `maxRequests`, `maxDurationMinutes`, `maxModelTurns`,
  `maxFindingsPerCategory`, `maxBodyBytes`, and `maxRedirects`.
- Human-in-the-loop gates for state-changing and destructive actions.
- `pentest` CLI command: `npm run pentest -- --scope <file>`.

Exit criteria:

- The loop starts only with a valid scope and stops on budget exhaustion,
  guardrail violations, or a planner halt.
- Deterministic checks still run when the model is unavailable.
- Every finding has evidence and a reproduction attempt.

## M5 — Verification and reporting

Goal: low false positives and machine- and human-readable output.

Deliverables:

- `src/report/markdown.ts`, `json.ts`, and `sarif.ts`.
- Baseline comparison and reproduction in the `verify` state.
- Coverage matrix for all in-scope categories.
- `report` CLI command.

Exit criteria:

- Only `confirmed` and `probable` findings are reported by default.
- Reports include methodology, coverage, budgets, and the audit log.

## M6 — End-to-end validation and CI

Goal: prove the engine works against known-vulnerable targets.

Deliverables:

- `test/unit`, `test/integration`, `test/target`, and `test/report`.
- Fixture baselines for Juice Shop, WebGoat, DVWA, and crAPI.
- CI: typecheck, build, tests, dependency scan, and SBOM.
- `npm run test` script.

Exit criteria:

- Guardrail tests pass (scope, deny, expiry, redirects, state-changing, rate
  limit, credential redaction).
- Fixture baselines show no unexplained findings or misses.

## M7 — v1.0 release

- Documentation matches the implemented CLI, scope format, and tool schemas.
- Release gates from `docs/verification.md` all pass.
- `npm run pentest` is documented with a real authorized scope example.

## Principles

- No phase weakens authorization, scope, rate limits, or evidence handling.
- Every phase ships with tests and updated docs.
- Deterministic checks remain independent of the LLM.
- Target responses are always untrusted data.
