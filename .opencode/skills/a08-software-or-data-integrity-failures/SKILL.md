---
name: A08 Software or Data Integrity Failures
description: Test and report OWASP A08 Software or Data Integrity Failures. Use when implementing or reviewing deserialization, unsigned updates, untrusted functionality, client-state integrity, or mass-assignment checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A08) and `docs/tool-reference.md`.

## Checks

- **Insecure deserialization** — detect serialization markers and untrusted
  data reaching deserializers; use safe, non-executing probes.
- **Unsigned updates** — auto-update endpoints without integrity verification.
- **Untrusted functionality** — third-party widgets/scripts included without
  integrity checks.
- **Cookie/client-state integrity** — reliance on unvalidated client state.
- **Mass assignment** — user-controlled fields modifying privileged attributes.

## Rules

- Deserialization probes must be harmless and non-executing.
- Do not download or execute untrusted artifacts.
- Only test components explicitly listed in the scope.

## False-positive control

- Require a distinguishable response, not just a serialization marker.
- Confirm the untrusted data is actually consumed by the deserializer.
- Distinguish client-state convenience from an integrity boundary.
