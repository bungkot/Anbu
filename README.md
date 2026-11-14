# ANBU - ANomaly-Based Understanding

**Agentic web security pentester** — a TypeScript engine that runs a bounded
agent loop over an authorized target and maps findings to the
[OWASP Top 10:2025](https://owasp.org/Top10/2025/).

ANBU combines deterministic, auditable security checks with LLM-guided
reasoning. It assesses web applications by examining their normal behavior and
identifying anomalies, suspicious requests, and potential vulnerabilities.
Designed for defensive security, ANBU tests only systems you are explicitly
authorized to assess, records evidence for every finding, and keeps a human in
the loop for any state-changing or destructive action.

> **Authorization is mandatory.** Do not run ANBU against any host, range, or
> application without written permission from the asset owner. See
> [`docs/scope-and-authorization.md`](docs/scope-and-authorization.md).

## Project status

ANBU has completed M0 (scaffolding), M1 (foundation), and M2 (tool layer and
evidence). The repository builds and runs the local Ollama/OpenCode
integration, and the engine can validate a scope, refuse out-of-scope or
unauthorized runs before any network call, crawl in-scope targets through the
guarded HTTP client, and store hashed, redacted evidence locally:

- `npm run doctor` — verifies Docker, Ollama, and the pinned model.
- `npm run ask -- "..."` — sends a prompt to the local model through the
  embedded OpenCode SDK.
- `npm run intake -- --scope scope/example.json` — validates a scope document
  and its authorization, with clear refusal reasons and a non-zero exit code.
- `npm run recon -- --scope scope/example.json` — read-only crawl and
  attack-surface summary (URLs, forms, assets, technologies, blocked requests).
- `npm run test` — runs the unit suite (scope, guardrails, authorization,
  rate limits, audit chain, intake, guarded HTTP, crawl, evidence, recon).

The OWASP checks, agentic loop, and reports are planned and tracked in
[`ROADMAP.md`](ROADMAP.md). Until then, the `pentest` and `report` commands do
not exist yet.

## How it works

```text
authorized scope
      │
      ▼
┌─────────────┐   ┌──────────────┐   ┌─────────────┐
│  recon      │──▶│  plan        │──▶│  execute    │
│  endpoints, │   │  select      │   │  guarded    │
│  forms,     │   │  OWASP checks│   │  HTTP tools │
│  tech stack │   │  (A01-A10)   │   │  + checks   │
└─────────────┘   └──────────────┘   └──────┬──────┘
                                            │
      ┌─────────────┐   ┌──────────────┐    │
      │  report     │◀──│  verify      │◀───┘
      │  Markdown / │   │  reproduce,  │
      │  JSON/SARIF │   │  kill FPs    │
      └─────────────┘   └──────────────┘
```

The loop is bounded by request, time, finding, and model-step budgets. Target
responses are always treated as untrusted data, never as instructions.

## OWASP Top 10:2025 coverage

| ID  | Category |
|-----|----------|
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

## Prerequisites
- Docker Desktop (Compose v2), VM memory >= 3 GiB
- Node.js >= 20 (optional when using the dev container)
- An Ollama model for LLM-guided reasoning (local, no cloud API key required)
- A written authorization and a scope file for the target

## Quick start

```bash
git clone <repo> && cd ANBU
./scripts/bootstrap.sh          # Docker memory check, .env, Ollama, model pull
npm install
npm run typecheck               # strict TypeScript + test types
npm run test                    # unit suite
npm run doctor                  # verify Ollama + model
npm run ask -- "Hello"          # try the local model through the OpenCode SDK
```

Running a real assessment requires the planned `pentest` command (M4 in
[`ROADMAP.md`](ROADMAP.md)):

```bash
npm run intake -- --scope scope/example.json   # validate scope + authorization
npm run recon -- --scope scope/example.json     # read-only attack surface
npm run pentest -- --scope scope/example.json   # planned (M4)
```

The scope file declares the targets, allowed test classes, rate limits, and the
authorization reference. Without a valid scope, the engine refuses to start.

## Run in Docker

The repository uses a single `docker-compose.yml` (Ollama + one app/dev service)
and a single `Dockerfile`. The default model is `granite3.3:2b` (1.5 GB Q4,
native function calling), sized for a 3 GB Docker Desktop VM.

```bash
npm run stack:build
npm run stack:up
docker compose exec app npm run doctor
npm run stack:ask -- "Hello"
```

Or open the folder in VS Code and use **Dev Containers: Reopen in Container**.
The repository is mounted at `/workspace`, `npm install` runs automatically, and
the dev container pins `OLLAMA_MODEL=granite3.3:2b` and pulls the model on first
setup (see `.devcontainer/devcontainer.json` and
`scripts/devcontainer-setup.sh`). The dev container reuses the single
`docker-compose.yml` and `Dockerfile`; there is no separate container setup.

## Documentation
- [Roadmap](ROADMAP.md)
- [Architecture](docs/architecture.md)
- [Agentic loop](docs/agentic-loop.md)
- [OWASP Top 10:2025 methodology](docs/methodology-owasp-top10-2025.md)
- [Scope and authorization](docs/scope-and-authorization.md)
- [Threat model](docs/threat-model.md)
- [Tool reference](docs/tool-reference.md)
- [Verification](docs/verification.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development
OpenCode loads `AGENTS.md` plus the agents, skills, and commands under
`.opencode/`. Start with the `architect` agent for design work and the
`pentester` agent for implementation. There are 10 OWASP Top 10:2025 category
skills and 10 matching category agents (`a01`-`a10`), plus the cross-cutting
`owasp-top10-2025` overview and `recon-and-scope` skills.

```bash
npm run typecheck   # src + test types
npm run test        # unit suite (node:test via tsx)
npm run build       # emit dist/
```

## License
[MIT](LICENSE)
