---
name: OWASP Top 10:2025
description: Master methodology for mapping tests and findings to the OWASP Top 10:2025. Use when planning coverage, classifying a finding, or writing a report.
---

## Categories (2025)

| ID | Category |
|---|---|
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

Do not use 2021 names. SSRF (CWE-918) belongs under A01, not a top-level
category.

## Workflow

1. Read `docs/methodology-owasp-top10-2025.md` for the full category map.
2. Load the matching category skill (`a01`-`a10`) for category-specific checks,
   rules, and false-positive controls.
3. For each in-scope category, select deterministic checks first, then
   model-guided probes.
4. Classify every finding with: category, CWE, five-band severity label,
   confidence, evidence, reproduction, remediation.
5. Reproduce before reporting; discard candidates explained by intended
   behavior.
6. Fill the coverage matrix; mark skipped categories `not_applicable` or
   `not_run` with a reason.

## Reporting checklist

- Exact 2025 category name and ID.
- CWE and five-band severity label.
- Affected URL, method, parameter.
- Sanitized evidence with content hash.
- Reproduction steps.
- False-positive analysis.
- Remediation mapped to the category's prevention controls.
- Coverage matrix included.

## Definition of done

A category is covered when at least one check ran and produced a result, or an
explicit reason is recorded. No finding is reported without evidence and
reproduction.
