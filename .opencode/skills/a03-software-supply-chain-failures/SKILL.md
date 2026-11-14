---
name: A03 Software Supply Chain Failures
description: Test and report OWASP A03 Software Supply Chain Failures. Use when implementing or reviewing dependency, SBOM, untrusted-source, unsigned-artifact, or CI/CD checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A03) and `docs/tool-reference.md`.

## Checks

- **Dependency inventory** — direct and transitive dependencies; versions.
- **Known vulnerabilities** — match against advisory data (OSV, NVD, GitHub
  Advisory) using an offline snapshot.
- **SBOM** — generate and validate an SBOM for the target project when source
  is available.
- **Untrusted sources** — dependencies from unofficial registries or URLs.
- **Unsigned artifacts** — updates, packages, or images without signatures.
- **CI/CD hardening** — separation of duties, branch protection, secrets in
  pipelines (only when the pipeline is in scope).

## Rules

- Dependency scanning is passive and read-only; do not exploit CVEs.
- Do not download or execute untrusted artifacts.
- Only test supply-chain systems explicitly listed in the scope.

## False-positive control

- Confirm the vulnerable version is actually reachable/used, not just present.
- Distinguish "outdated" from "vulnerable with exploit path".
