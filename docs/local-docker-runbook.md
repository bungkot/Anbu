# Local Docker Runbook

Step-by-step guide for a local trial run of the anbu stack (Ollama + OpenCode
SDK) using Docker Compose.

## Prerequisites

- Docker Desktop running with at least ~3 GB memory available
  (2 GB Ollama + 0.75 GB app + headroom).
- Node.js >= 20.19.0 on the host (for npm scripts and builds).
- The compose stack uses the model `granite3.3:2b` by default (1.5 GB Q4,
  fits the 2 GB Ollama limit together with the 8192-token q8_0 KV cache).

## 1. Prepare configuration

```powershell
copy .env.example .env
```

Defaults are safe for a first run:

| Variable | Default | Notes |
| --- | --- | --- |
| `OLLAMA_MODEL` | `granite3.3:2b` | Apache 2.0, native function calling |
| `OLLAMA_MEM_LIMIT` | `2g` | Model + KV cache must fit |
| `APP_MEM_LIMIT` | `0.75g` | App container |
| `OLLAMA_CONTEXT_LENGTH` | `8192` | Lower to 4096 if OOM |
| `ANBU_SCOPE_FILE` | `scope/example.json` | Placeholder scope, replace (step 5) |
| `ANBU_EVIDENCE_DIR` | `workspace/evidence` | Evidence output |
| `ANBU_READ_ONLY` | `true` | Read-only probing by default |

Inside Docker the Ollama base URL is forced to `http://ollama:11434/v1`; the
`OLLAMA_BASE_URL` value only applies when running on the host.

## 2. Build and start the stack

```powershell
npm run stack:build
npm run stack:up
```

The `app` container waits for the `ollama` healthcheck before starting.

## 3. Pull the model into the Ollama container

The model is not pulled automatically on `up`:

```powershell
docker compose exec ollama ollama pull granite3.3:2b
```

(~1.5 GB, one time; stored in the `ollama` volume.)

## 4. Health check (doctor)

```powershell
npm run stack:exec -- doctor
```

Or on the host after a build:

```powershell
npm run build
npm run doctor
```

This verifies Ollama is reachable and the model is available.

## 5. Prepare the scope (required)

The default `scope/example.json` is a placeholder (`test.example.com`).
Create a scope that points at a target you are explicitly authorized to test,
for example a local test app reachable from the compose network
(`http://host.docker.internal:PORT` or another compose service):

1. Copy `scope/example.json` to `scope/local.json`.
2. Edit `targets[]`: set `host`, `scheme`, `port`, `paths` (and `methods`).
3. Set `ANBU_SCOPE_FILE=scope/local.json` in `.env`.
4. If the scope references a token (`env:ANBU_AUTH_TOKEN`), fill in
   `ANBU_AUTH_TOKEN` in `.env`. Never commit a real token.
5. Validate:

```powershell
npm run stack:exec -- intake --scope scope/local.json
```

> Warning: the example `deny` rules block `10.0.0.0/8` and `*.example.com`
> paths such as `/admin/delete` and `/internal`. Make sure your local target
> is not rejected by the deny list.

## 6. Run recon, then pentest

```powershell
npm run stack:exec -- recon --scope scope/local.json
npm run stack:exec -- pentest --scope scope/local.json
```

Budgets are enforced from the scope document and `.env`
(`ANBU_MAX_REQUESTS`, `ANBU_MAX_DURATION_MINUTES`, `ANBU_MAX_MODEL_TURNS`,
`ANBU_REQUESTS_PER_SECOND_PER_HOST`, ...).

State-changing tests stay blocked while `ANBU_READ_ONLY=true`; they require
the explicit approval gate.

## 7. Generate the report

```powershell
npm run stack:exec -- report
```

Evidence is written to `ANBU_EVIDENCE_DIR` (default `workspace/evidence`).

## Quick command reference

| Command | Purpose |
| --- | --- |
| `npm run stack:build` | Build the `app` image |
| `npm run stack:up` | Start Ollama + app |
| `npm run stack:down` | Stop the stack |
| `npm run stack:logs` | Follow Ollama logs |
| `npm run stack:exec -- <args>` | Run the CLI inside the app container |
| `npm run stack:ask` | Run `ask` as a one-off container |
| `npm run dev -- <cmd>` | Run the CLI from source on the host |

## Troubleshooting

- **OOM / model fails to load**: lower `OLLAMA_CONTEXT_LENGTH`
  (e.g. `4096`) in `.env`, then `npm run stack:down && npm run stack:up`.
- **Model not found**: re-run the pull in step 3 and check
  `docker compose exec ollama ollama list`.
- **Interactive shell in the app container**:
  `docker compose exec app bash` (repository mounted at `/workspace`).
- **Scope refused**: run `intake` again and check the deny rules, path
  patterns, and validity dates (`validFrom` / `validUntil`).
