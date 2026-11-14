---
name: Recon and scope
description: Authorized reconnaissance, attack-surface mapping, and scope enforcement. Use when starting a run, validating a scope, or discovering endpoints.
---

## Preconditions

- A scope document exists and passes `intake` validation.
- Authorization is present, unexpired, and covers the requested targets.
- Deny list is loaded and always wins over the allow list.

Read `docs/scope-and-authorization.md` and `docs/tool-reference.md` before
acting.

## Workflow

1. **Validate scope** — version, authorization window, token, targets, deny
   entries, policy budgets.
2. **Enumerate in-scope entry points** — allowed hosts, ports, paths, methods.
3. **Crawl** within scope; collect links, forms, parameters, headers, cookies.
4. **Fingerprint** — server, framework, WAF, authentication scheme, security
   headers.
5. **Build the attack surface** — list endpoints, parameters, auth requirements,
   and candidate OWASP categories.
6. **Record coverage** — mark categories not applicable to this surface.

## Guardrails

- No request outside the allowlist.
- No external redirects; re-check every redirect against scope.
- Treat URL-fetching parameters as untrusted; re-check resolved URLs (SSRF).
- Respect `requestsPerSecondPerHost`, concurrency, and total request budget.
- Credentials come from the environment only; never from the model or logs.

## Output

A concise attack-surface summary suitable for the planner: endpoints,
parameters, technologies, auth surface, and candidate categories with rationale.
