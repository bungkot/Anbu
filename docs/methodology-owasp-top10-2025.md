# OWASP Top 10:2025 methodology

This document defines how Anbu selects, executes, and reports tests. The
category names and IDs follow the official
[OWASP Top 10:2025](https://owasp.org/Top10/2025/) release.

## 1. Category map

| ID | Category | What Anbu tests | Representative CWEs |
|---|---|---|---|
| A01 | Broken Access Control | IDOR/BOLA, force browsing, privilege escalation, missing authorization on POST/PUT/DELETE, CORS misconfiguration, JWT/cookie tampering, path traversal | CWE-284, 862, 863, 918, 352, 639, 22, 601 |
| A02 | Security Misconfiguration | default credentials, directory listing, verbose errors/stack traces, missing security headers, unnecessary features, insecure cookie flags, cloud storage permissions | CWE-16, 489, 611, 1004, 614, 526, 547 |
| A03 | Software Supply Chain Failures | outdated/vulnerable dependencies, untrusted sources, unsigned artifacts, weak CI/CD controls, missing SBOM | CWE-1104, 1329, 1395, 1357, 1035 |
| A04 | Cryptographic Failures | weak TLS, deprecated algorithms, key management, weak password hashing, insufficient randomness, missing HSTS, sensitive data in transit | CWE-327, 331, 338, 759, 916, 319, 296 |
| A05 | Injection | SQL injection, XSS (reflected/stored/DOM), OS command injection, LDAP, ORM/HQL, expression language, SSTI, XXE, CRLF | CWE-89, 79, 78, 90, 917, 94, 91, 113 |
| A06 | Insecure Design | business-logic abuse, missing rate limits, trust-boundary violations, unsafe workflow assumptions, unrestricted upload, credential storage design | CWE-501, 807, 841, 799, 434, 522 |
| A07 | Authentication Failures | credential stuffing (only with test accounts), brute force, default/weak passwords, session fixation, logout/session invalidation, weak recovery, missing MFA | CWE-287, 307, 384, 613, 798, 1392, 640 |
| A08 | Software or Data Integrity Failures | insecure deserialization, unsigned updates, untrusted functionality, cookie integrity, reliance on unvalidated client state | CWE-502, 494, 829, 915, 565, 784 |
| A09 | Security Logging and Alerting Failures | missing login/access-control logs, sensitive data in logs, log injection, missing alerting, log integrity | CWE-778, 532, 117, 223 |
| A10 | Mishandling of Exceptional Conditions | fail-open behavior, sensitive error messages, missing parameter handling, resource exhaustion, race conditions, missing transaction rollback | CWE-636, 209, 703, 754, 460, 362 |

> Naming note: the 2025 list replaces "Vulnerable and Outdated Components"
> (A06:2021) with **A03 Software Supply Chain Failures**, replaces
> "Identification and Authentication Failures" with **A07 Authentication
> Failures**, and adds **A10 Mishandling of Exceptional Conditions**. SSRF
> (CWE-918) remains in scope under A01 Broken Access Control.

## 2. Test lifecycle per category

1. **Detect surface** — identify endpoints, parameters, auth requirements, and
   technologies relevant to the category.
2. **Select checks** — choose deterministic checks and model-guided probes.
3. **Execute safely** — read-only first; state-changing only under policy.
4. **Capture evidence** — store request/response with a content hash.
5. **Verify** — reproduce the candidate and rule out false positives.
6. **Classify** — assign category, CWE, severity, confidence.
7. **Remediate guidance** — map to the OWASP prevention controls for that
   category.

## 3. Deterministic checks vs model-guided probes

| Layer | Examples | When to use |
|---|---|---|
| Deterministic | header analysis, TLS version, cookie flags, dependency CVE lookup, SQL error signatures, XSS reflection, path traversal probes | High signal, low ambiguity, always run first |
| Model-guided | business-logic abuse, chained findings, unusual workflows, report synthesis | Ambiguous, creative, or multi-step reasoning |

Deterministic checks must not depend on the LLM. Model-guided probes must use
the same guarded tools and produce the same finding shape.

## 4. Severity and confidence model

Findings carry a five-band severity label and a confidence value.

| Severity | Meaning |
|---|---|
| `critical` | Remote code execution, full authentication bypass, mass data exposure |
| `high` | Direct data access, privilege escalation, injection with impact |
| `medium` | Limited exposure, requires conditions, defense-in-depth gaps |
| `low` | Hard to exploit, minimal impact, best-practice deviation |
| `informational` | Observation, not a vulnerability |

Confidence values:

- `confirmed` — the originating check reproduced the finding and the
  reproduced response matched the captured evidence.
- `probable` — the finding has valid evidence but was not reproduced (for
  example the reproduction budget was reached, or the check is state-changing
  and approval was not granted).
- `unverified` — withheld candidate; never reported by default.

Only `confirmed` and `probable` findings are reported by default.

## 5. Evidence requirements

Every reported finding must include:

- Target URL, method, and parameter.
- Request and response metadata (status, headers, timing).
- Sanitized request/response bodies with a content hash.
- Exact reproduction steps.
- Why the behavior is a vulnerability, not intended functionality.
- Mapped OWASP category, CWE, severity, and confidence.
- Remediation mapped to OWASP prevention guidance.

Raw credentials, tokens, session cookies, and personal data must be redacted
from evidence before it is stored or rendered.

## 6. False-positive control

- Reproduce every candidate before reporting.
- Compare against a baseline request (same endpoint without the payload).
- Check whether the behavior is required by the application's documented
  purpose.
- Prefer specific, high-signal payloads over noisy fuzzing.
- Track false-positive rate per check and disable or tune checks that exceed the
  threshold (default 10%).
- Report coverage and confidence so a human can triage.

## 7. Coverage matrix

A run is complete when every in-scope category has either:

- at least one executed check with results (`covered`), or
- an explicit `not_applicable` / `not_run` reason recorded.

The report always includes the coverage matrix so gaps are visible.

## 8. Anti-patterns

- Do not report a finding without evidence or reproduction.
- Do not treat a single anomalous response as proof.
- Do not use the 2021 category names in reports.
- Do not run destructive checks to "confirm" a finding.
- Do not send target data to a third-party model when a local model is
  configured.
