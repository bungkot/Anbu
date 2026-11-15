# Reading a report

Every `pentest` run writes a run directory under `workspace/evidence/<run-id>/`.
The directory is the unit of evidence: it holds the rendered views, the raw
report, the append-only audit log, and the captured artifacts for that run.

```text
workspace/evidence/<run-id>/
├── report.json      # source of truth for the run
├── report.md        # human-readable view (default)
├── report.sarif     # SARIF view for tooling
├── audit.log        # append-only, hash-chained event log
├── llm/
│   ├── backlog.md       # readable prompt/response study log
│   └── exchanges.jsonl  # machine-readable prompt/response stream
└── artifacts/       # redacted request/response evidence, named by content hash
```

The `llm/` directory is written only when the model planner ran and recorded at
least one turn. It captures every prompt sent to the model and every response,
which is useful for learning how the planner reasons. Model output in the
backlog is untrusted data, redacted best-effort for credentials.

`report.md` and `report.sarif` are rendered from `report.json`. To render an
existing run again:

```bash
npm run report -- --run workspace/evidence/<run-id>
npm run report -- --run workspace/evidence/<run-id> --format sarif
npm run report -- --run workspace/evidence/<run-id> --out report.md
```

By default the Markdown and SARIF views include only `confirmed` and `probable`
findings. Add `--all` to include discarded candidates. `report.json` always
contains every candidate.

## Recommended reading order

Read top to bottom, but start with two questions: **how bad is it** (Executive
summary) and **did the run finish normally** (Stop reason).

### 1. Header

```markdown
- **Run ID:** 14e8e640-5e52-456b-810c-0ab821896e4c
- **Scope authorization:** LOCAL-LAB-2026-001
- **Generated:** 2026-11-14T21:51:14.622Z
- **Stop reason:** completed
- **Report version:** 1
```

- **Run ID** matches the run directory name.
- **Scope authorization** is the reference to the authorization document. It
  records that the run stayed inside an approved scope.
- **Stop reason** says why the loop ended. Possible values: `completed`,
  `budget_exhausted`, `guardrail_streak`, `tool_failure_streak`, `planner_halt`,
  `human_stop`, `model_unavailable`. Anything other than `completed` means the
  run was cut short and coverage may be incomplete.
- **Report version** is the envelope version, currently `1`.

### 2. Executive summary

```markdown
Reported findings: **4** (4 confirmed, 0 probable)

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 3 |
| INFORMATIONAL | 0 |
```

Only `confirmed` and `probable` findings are counted. Candidates that could not
be reproduced, lacked valid evidence, or needed an approval that was not granted
are withheld; when any were withheld, a line such as `N candidate(s) were
withheld because they were not confirmed or probable.` appears under the table.
Use the severity table to prioritise remediation.

### 3. Methodology

Records how the run was performed:

- **Framework:** OWASP Top 10:2025.
- **Approach:** whether the LLM planner ran. `the LLM planner was unavailable, so
  only deterministic checks ran` means the results come only from deterministic
  checks.
- **Deterministic checks:** how many registered checks were available to run.
- **Model-assisted:** `yes` or `no`.
- **Verification:** the rule that every candidate finding is reproduced by
  re-running its originating check against captured evidence.

### 4. Coverage

```markdown
| Category | Name | Status | Checks | Findings |
|---|---|---|---|---|
| A01 | Broken Access Control | covered | 5 | 0 |
| A09 | Security Logging and Alerting Failures | covered | 1 | 1 |
```

Status values:

| Status | Meaning |
|---|---|
| `covered` | At least one registered check for the category ran. |
| `not_applicable` | The scope excludes the category. |
| `not_run` | The category was in scope but no check ran. |

`not_run` is a coverage gap, not a clean result. A zero in the `Findings` column
means no reported finding, not that the category is secure.

### 5. Budgets

```markdown
| Budget | Used | Maximum |
|---|---|---|
| Requests | 26 | 800 |
| Duration (minutes) | 10.1 | 60 |
| Model turns | 2 | 10 |
```

Shows how much of each bound the run consumed. When `Used` is close to
`Maximum`, the run was likely truncated and coverage may be incomplete.

### 6. Findings

Each finding has a fixed shape:

```markdown
### 1. [MEDIUM] Content-Security-Policy header is missing

- **ID:** `sha256:75101b...`
- **Category:** A02 Security Misconfiguration
- **CWE:** CWE-693
- **Status:** confirmed (confidence: confirmed)
- **Affected:** http://host.docker.internal:3000/

**Reproduction**

1. Send a GET request to http://host.docker.internal:3000/ and inspect the response headers.

**Evidence**

- `sha256:5998f66c...` — artifacts/5998f66c....json

**Remediation**

Deploy a restrictive Content-Security-Policy appropriate to the application; avoid `unsafe-inline` and `unsafe-eval`.

**Details:** CSP was absent from the response.

- **Verification:** confirmed — the originating check reproduced the finding; the reproduced response matches the captured baseline (`sha256:dc1bac69...`)
```

| Field | Meaning |
|---|---|
| **ID** | Stable `sha256:` content identifier for the finding. |
| **Category** | OWASP Top 10:2025 category ID and name. |
| **CWE** | Weakness identifier, when one applies. |
| **Status / confidence** | Verification outcome and engine confidence. |
| **Affected** | URL and, when relevant, the parameter that triggered the finding. |
| **Reproduction** | Steps to reproduce the finding. Empty means none were recorded. |
| **Evidence** | `sha256:` evidence IDs and artifact paths relative to the run directory. Open the artifact to inspect the captured request/response. |
| **Remediation** | Suggested fix. |
| **Details** | Extra deterministic context (matched markers, versions, headers). |
| **False-positive analysis** | Why the finding might be a false positive, when the engine flags one. |
| **Verification** | `confirmed`, `probable`, or `discarded`, with the reason and any evidence ID. |

Findings appear in the order they were produced during the run, not sorted by
severity. Use the Executive summary table to prioritise, then read individual
findings.

### 7. Audit log

```markdown
- **Path:** workspace/evidence/<run-id>/audit.log
- **Entries:** 85
- **Integrity:** ok

| Seq | Timestamp | Event | Decision | Reason |
|---|---|---|---|---|
| 22 | 2026-11-14T21:41:08.550Z | guardrail | deny | per-host rate limit exceeded for host.docker.internal |
| 74 | 2026-11-14T21:51:13.188Z | verify.confirmed |  | the originating check reproduced the finding; ... |
```

- **Integrity:** `ok` means the append-only hash chain is intact. `failed`
  (with **Broken at sequence**) means the log is inconsistent and its contents
  need investigation before they are trusted. `unknown` means it could not be
  verified.
- Common events: `run.start`, `run.end`, `guardrail` (`allow`/`deny`), `check`,
  `finding`, `verify.confirmed`, `planner.error`, `planner.disabled`.
- Guardrail denials and planner errors explain why coverage or model assistance
  was limited.

### 8. LLM backlog

When the planner ran, `llm/backlog.md` lists each turn with the agent prompt,
system prompt, user prompt, model response, duration, and result. Use it to see
which checks the model selected and why. `llm/exchanges.jsonl` is the same data
as one JSON object per turn for scripting. `pentest` prints the backlog path at
the end of a run.

### 9. Footer

> Generated by Anbu. Target responses are untrusted data; findings require
> human review.

The rendered report is a starting point for human review, not a final
attestation.

## Terminology

| Term | Meaning |
|---|---|
| **Severity** | Technical impact: `critical`, `high`, `medium`, `low`, `informational`. |
| **Confidence** | Engine confidence: `confirmed`, `probable`, `unverified`. |
| **Status** | Verification outcome: `candidate`, `confirmed`, `probable`, `discarded`. |
| **Reported** | `confirmed` plus `probable`. `discarded` findings are hidden by default. |
| **Verification confirmed** | The originating check was re-run and matched the captured baseline. |
| **Verification probable** | The finding was kept but could not be fully reproduced. |

## Quick checklist

1. Is **Stop reason** `completed`? If not, find the limiting factor.
2. Does **Coverage** contain `not_run`? Those are gaps, not zero-finding results.
3. Is **Model-assisted** `no`? Findings are limited to deterministic checks.
4. Are **Budgets** near their maxima? Coverage may be truncated.
5. Read the **Executive summary**, then the high-severity findings.
6. For each finding: check **Affected**, follow **Reproduction**, open the
   **Evidence** artifact, then read **Verification**.
7. Check the **Audit log**: `Integrity: ok`, and look for `deny` or
   `planner.error` events that explain the run's limits.
