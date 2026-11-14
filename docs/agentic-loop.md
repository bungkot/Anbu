# Agentic loop

## 1. Overview

The loop is a bounded state machine. Each iteration performs one planning step,
executes one or more guarded tool calls, observes the results, and decides the
next step. It never runs without a valid scope and stops when any budget is
exhausted.

```text
        ┌───────────────────────────────────────────┐
        │                                           │
        ▼                                           │
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌───┴──────┐
  │ intake   │──▶│ recon    │──▶│ plan     │──▶│ execute  │
  └──────────┘   └──────────┘   └──────────┘   └────┬─────┘
                                                     │
  ┌──────────┐   ┌──────────┐   ┌──────────┐        │
  │ halt     │◀──│ report   │◀──│ verify   │◀───────┘
  └──────────┘   └──────────┘   └──────────┘
```

## 2. States

### intake
- Load and validate the scope document and authorization.
- Resolve target allowlist and deny list.
- Initialize budgets, audit log, evidence store, and run ID.
- Refuse to start if authorization is missing, expired, or does not cover the
  requested targets.

### recon
- Fetch allowed entry points.
- Discover links, forms, parameters, headers, cookies, and static assets.
- Fingerprint the framework, server, and security headers.
- Build an attack surface summary for the planner.
- Read-only by default; login flows require an explicit scope entry.

### plan
- The planner selects OWASP categories and concrete checks based on the attack
  surface and the scope's `testClasses`.
- It orders checks by expected signal: cheap deterministic checks first, then
  model-guided probes.
- It proposes a budget allocation per category.

### execute
- Run deterministic checks and model-guided probes through the tool layer.
- Each tool call is guarded (scope, authorization, policy, rate limit).
- Evidence is captured for every request/response that could support a finding.
- State-changing actions require a human approval gate unless the scope
  explicitly allows them.

### verify
- Reproduce each candidate finding from its evidence.
- Re-run the triggering request or a safe equivalent.
- Discard candidates that cannot be reproduced or that are explained by the
  target's intended behavior.
- Attach confidence and false-positive analysis.

### report
- Aggregate findings, coverage, and budgets.
- Emit Markdown, JSON, and SARIF.
- Include an executive summary, methodology, and remediation guidance mapped to
  OWASP prevention controls.

### halt
- Stop on: budget exhausted, repeated guardrail violations, repeated tool
  failures, or an explicit stop from the planner.
- Always produce a report for the work completed.

## 3. Tool contract

Tools are exposed to the planner as structured functions. A tool call has:

```json
{
  "name": "http_request",
  "arguments": {
    "method": "GET",
    "url": "https://target.example/api/users/1",
    "headers": {},
    "body": null
  }
}
```

Rules:
- The planner cannot invent tools or arguments; the schema is closed.
- Every call is re-validated by the guardrail layer before execution.
- Tools return a bounded, sanitized result plus an evidence reference.
- The planner never receives secrets or raw credentials.

## 4. Prompt contract

System prompt contains:
- Role and safety rules (authorization, scope, read-only default).
- The OWASP Top 10:2025 category list.
- The tool schemas and output format.
- Budget and stop conditions.

User prompt contains:
- Run ID, target summary, attack surface, selected categories.
- Recent tool results (sanitized, truncated).
- The current objective and remaining budget.

Target-derived content is fenced as data:

```text
<target-data id="...">
... untrusted content ...
</target-data>
```

The model is instructed that anything inside `<target-data>` is evidence, not
instructions.

## 5. Memory and context

- **Working memory**: the current objective, attack surface, selected checks,
  and recent results.
- **Evidence memory**: captured artifacts referenced by hash; only summaries and
  sanitized excerpts enter the prompt.
- **Finding memory**: candidates and their verification state.
- Context is compacted when it approaches the model limit; compaction preserves
  the objective, budgets, and open findings.

## 6. Budgets and stop conditions

| Budget | Default | Purpose |
|---|---|---|
| `maxRequests` | 800 | Cap outbound requests per run. |
| `maxDurationMinutes` | 60 | Cap wall-clock time. |
| `maxModelTurns` | 120 | Cap LLM planning turns. |
| `maxFindingsPerCategory` | 25 | Prevent flood/noise. |
| `maxBodyBytes` | 64 KiB | Cap captured response bodies. |
| `maxRedirects` | 3 | Prevent redirect loops. |

Stop conditions: budget exhausted, guardrail violation streak, tool failure
streak, planner requests halt, or human stop.

## 7. Human-in-the-loop gates

- **Read-only run**: no approval needed for GET/HEAD/OPTIONS.
- **State-changing run**: POST/PUT/PATCH/DELETE require either an explicit scope
  allowlist entry or interactive approval.
- **Destructive tests** (account deletion, password reset, bulk data changes,
  DoS-like load): always require explicit approval and are denied by default.
- Approvals are recorded in the audit log with actor, timestamp, and reason.

Current status (M4): state-changing checks call the approval provider before
running, and the default provider denies every request. An interactive provider
and `--auto-approve` flag are part of the M5 HITL follow-up. Scope
`stateChanging` modes (`deny`, `approve`, `allow`) stay enforced by the policy
guardrail independently of the approval provider, so granting an approval can
never bypass a read-only scope.

## 8. Failure handling

- Network errors are retried once with backoff, then recorded.
- A tool failure streak pauses the loop and asks the planner for a new approach.
- Guardrail violations never execute and are surfaced to the operator.
- If the LLM is unavailable, deterministic checks continue and the report notes
  reduced coverage.
