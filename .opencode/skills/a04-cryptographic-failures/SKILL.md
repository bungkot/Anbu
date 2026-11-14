---
name: A04 Cryptographic Failures
description: Test and report OWASP A04 Cryptographic Failures. Use when implementing or reviewing TLS, data-in-transit, key management, password storage, randomness, or cryptographic-error checks.
---

Read `docs/methodology-owasp-top10-2025.md` (A04) and `docs/tool-reference.md`.

## Checks

- **TLS** — version >= 1.2, forward secrecy, weak ciphers, certificate chain,
  hostname validation, HSTS.
- **Data in transit** — sensitive data over cleartext or weak protocols.
- **Key management** — hardcoded keys, default keys, missing rotation.
- **Password storage** — weak/deprecated hashes (MD5, SHA1), unsalted hashes,
  insufficient work factor.
- **Randomness** — predictable tokens/IDs, weak PRNG usage.
- **Cryptographic errors** — padding oracles, algorithm downgrade.

## Rules

- Prefer pass/fail checks with clear evidence.
- Do not fetch external resources during cryptographic probes.
- Do not store sensitive data from the target.

## False-positive control

- Confirm the protocol/cipher is actually negotiated, not merely offered.
- Distinguish deprecated algorithm support from an exploitable path.
- Validate certificate/hostname issues against the real service identity.
