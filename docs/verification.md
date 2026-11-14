# Verification

Verification covers two things: the correctness of Anbu's code, and the
quality of its findings.

> Status: unit tests are implemented and run with `npm run test`, including a
> vulnerable and a safe fixture for every deterministic check under
> `test/unit/checks/`, agent-loop coverage (budgets, planner parsing, approval
> gates, stop reasons, deterministic fallback, verification) under
> `test/unit/agent/`, and report rendering (Markdown, JSON, SARIF, discarded
> handling) under `test/unit/report/`. Integration and target suites are
> planned; see `ROADMAP.md`.

## 1. Levels

| Level | What it proves | Where |
|---|---|---|
| Unit | A check detects a known-vulnerable fixture and ignores a safe one. | `test/unit` |
| Integration | The loop, guardrails, and evidence store work end to end. | `test/integration` |
| Target | The engine runs against a deliberately vulnerable application. | `test/target` |
| Report | Findings, severity, coverage, and evidence are accurate; only confirmed/probable findings reach the rendered views. | `test/unit/report` |

## 2. Safe target applications

Use intentionally vulnerable applications that you run locally. Never use a
production system or a system you do not own.

Recommended fixtures (run in Docker, never exposed to the internet):
- **OWASP Juice Shop** — broad coverage of A01-A10.
- **OWASP WebGoat** — injection, auth, access control.
- **DVWA** — classic injection and misconfiguration.
- **OWASP crAPI** — API/BOLA and supply-chain issues.
- **Vulnerable Node/Express sample** — for deterministic check unit fixtures.

Each fixture run produces a baseline of expected findings. A regression is a
new miss (false negative) or a new unexpected finding (false positive).

Target recorded for M6: **`https://demo.testfire.net/`** (Altoro Mutual,
a deliberately vulnerable demo application). It is an external host, so it may
only be exercised with a written authorization from the asset owner and a valid
scope document; never run it outside those guardrails. Local Docker fixtures
above are preferred when an authorized external target is unavailable.

## 3. Unit test policy

For every check:
- A vulnerable fixture must produce a finding.
- A safe fixture must not produce a finding.
- Guardrail tests must prove that out-of-scope and denied requests are blocked.
- A check that exceeds a 10% false-positive rate on the fixture suite is
  disabled or tuned before merge.

## 4. End-to-end run

```bash
npm run build
npm run typecheck
npm run test
docker run --rm -p 3000:3000 bkimminich/juice-shop
npm run pentest -- --scope scope/juice-shop.local.json
```

Validate:
- The run starts only with a valid scope.
- Every candidate finding is reproduced by re-running its originating check;
  candidates that cannot be reproduced are withheld from Markdown/SARIF.
- Every finding has evidence and reproduction steps.
- The coverage matrix matches the scope's `testClasses`.
- Budgets and stop reason are reported.
- The audit log is complete and append-only.
- The run directory contains `report.json`, `report.md`, and `report.sarif`,
  and `npm run report -- --run <dir>` renders them again.

## 5. Guardrail tests

At minimum, prove:
- Out-of-scope host is blocked.
- Denied path is blocked even when the host is allowed.
- Expired authorization blocks the run.
- External redirect is not followed.
- State-changing request requires approval.
- Rate limit and request budget are enforced.
- Credentials and tokens never appear in logs, evidence, or prompts.

M1 implements the first six in `test/unit` (`scope.test.ts`, `policy.test.ts`,
`authorization.test.ts`, `rate-limit.test.ts`, `intake.test.ts`). M2 adds the
redirect, credential-redaction, and evidence tests (`http.test.ts`,
`crawl.test.ts`, `evidence-store.test.ts`, `evidence.test.ts`,
`recon.test.ts`). M4 adds loop-level guardrail tests (`loop.test.ts`): an
invalid scope refuses before any network call, out-of-scope planner actions
never reach fetch, approval is required before state-changing checks, and
granting approval does not bypass the read-only policy.

## 6. Finding quality metrics

Track per release:
- **False-positive rate** per check and overall (target < 10%).
- **Coverage**: categories executed / categories in scope.
- **Reproduction rate**: confirmed / reported findings (target 100%).
- **Signal**: findings per 1,000 requests.
- **Time to first confirmed finding**.

## 7. CI

- Typecheck and build on every change.
- Unit and integration tests on every change.
- Dependency vulnerability scan (A03) on the project itself.
- Optional nightly run against local fixtures; results reviewed before release.

## 8. Release gates

- No known-vulnerable dependencies.
- All guardrail tests pass.
- No unchecked or unverified findings in fixture baselines.
- Documentation matches the implemented CLI, scope format, and tool schemas.
