# Ollama staged model tests

`.github/workflows/ollama-smoke.yml` exercises Anbu against a real Ollama model
on a GitHub-hosted runner. It is deliberately separate from `ci.yml`: the model
download is several gigabytes, so this workflow runs on manual dispatch and a
weekly schedule instead of on every push or pull request.

The workflow is staged so a slow or flaky model does not hide the deterministic
guarantees. A manual run can stop at any stage; the weekly schedule runs all
three.

## Triggering

This workflow **does not run on push**. A green `CI` run only covers
typechecking, linting, build, tests, audit, and SBOM; it does not download or
call Ollama.

To run the model stages:

1. Open **Actions → Ollama staged model tests**.
2. Choose **Run workflow**.
3. Select the deepest stage (`smoke`, `deterministic`, or `model`) and start it.

The first run downloads the Ollama archive and the 4.9 GB model, so expect
several minutes before the first model step appears. The weekly schedule runs
the `model` stage automatically.

| Stage | What runs | Blocking? |
| --- | --- | --- |
| 1. Smoke | `doctor`, direct Ollama benchmark, `ask` through the OpenCode SDK | Yes |
| 2. Deterministic | Juice Shop, `intake`, `pentest --no-model` | Yes |
| 3. Model-guided | `pentest` with the planner, capped by `maxModelTurns` | No (experimental) |

Select the deepest stage with **Run workflow → stage**:

- `smoke` — model installation, benchmark, and `ask` only.
- `deterministic` — smoke plus the read-only deterministic pentest.
- `model` — all three stages, including the experimental planner run.

The weekly schedule uses `model`.

## What it measures

Stage 1 writes concrete CPU-inference numbers to the job summary and to the
`metrics` artifact:

- Model load time.
- Prompt evaluation tokens per second.
- Generation tokens per second.
- Generated token count.
- End-to-end `ask` wall time.

Stages 2 and 3 add wall time, request budget usage, model-turn usage, stop
reason, whether the planner was used, and reported/withheld findings. The
summary is rendered as a Markdown table on the workflow run page, so performance
changes are visible without reading raw logs.

Stage 1 calls `/api/generate` directly before `ask`. That warms the model and
measures it independently of OpenCode overhead. `ask` then measures the full
SDK path.

## What it proves

- Ollama starts on the runner and serves the pinned model.
- `doctor` finds the model through the configured OpenAI-compatible endpoint.
- `ask` gets a non-empty answer from the model through the OpenCode SDK.
- Anbu validates an explicit scope and completes a read-only deterministic
  pentest against an ephemeral OWASP Juice Shop container.
- The planner can run against the same target with a hard model-turn budget.
- Evidence, metrics, the Ollama log, and the model answer are uploaded as
  artifacts.

Stage 3 is experimental and non-blocking. A CPU-only runner can exceed the
SDK's 300-second planner request timeout, which is the same failure mode seen on
slow local hardware. When that happens the step outcome is `failure` and the
summary shows `n/a` or `deterministic only`, but the workflow does not fail.
Stages 1 and 2 remain the release-relevant gates.

## Runner assumptions

The workflow targets the standard public-repository `ubuntu-latest` runner
(4 vCPU, 16 GB RAM, 14 GB SSD). Private repositories receive a smaller runner,
so model calls will be slower and the job may need a longer timeout.

| Resource | Choice | Reason |
| --- | --- | --- |
| Model | `dolphin3:8b` | Uncensored Llama 3.1 8B, 4.9 GB, 128K context, strong instruction following; fits CPU-only inference. |
| Ollama | `v0.40.16`, `ollama-linux-amd64.tar.zst` | Pinned release, verified against the published SHA-256. |
| Juice Shop | `bkimminich/juice-shop@sha256:877fc77b...` | Digest pin keeps the lab target reproducible. |
| OpenCode CLI | `opencode-ai@1.19.5` | Pinned in `package-lock.json` to match `@opencode-ai/sdk`. |

Ollama is installed natively rather than from the `ollama/ollama` container
image. The image is roughly 8.5 GB before the model, while the native archive is
about 1.5 GB. The workflow extracts the archive, removes the CUDA, MLX, Vulkan,
and include payloads that a CPU-only runner cannot use, and verifies the
remaining installation with `ollama --version`.

## Steps

1. Free runner disk space and check `df -h /`.
2. `npm ci` and `npm run build`.
3. Download and checksum the pinned Ollama archive, install it under
   `/usr/local`, and strip GPU payloads.
4. Start `ollama serve`, wait for `/api/tags`, then pull `dolphin3:8b`.
5. Print `ollama list`, `ollama show`, and later `ollama ps` so the loaded
   model and its metadata are visible in the job log.
6. Put `node_modules/.bin` on `PATH` so the embedded OpenCode server can find
   the local `opencode` CLI (with a pinned global install as fallback).
7. Run `doctor`.
8. Stage 1: benchmark `/api/generate`, then `ask`.
9. Stage 2: start Juice Shop, validate scope, then `pentest --no-model`.
10. Stage 3: run `pentest` with the planner; the scope caps it at two model
    turns. Print a compact model-assisted/stop-reason/turn summary to the log.
11. Render the stage summary, upload evidence and metrics, and always stop
    Juice Shop and Ollama.

## Scope and authorization

`scope/ci-juice-shop.json` targets only `http://127.0.0.1:3000`, is read-only,
and caps each pentest at 400 requests and 20 minutes. Stage 3 is additionally
capped at two model turns. Authorization uses `env:ANBU_AUTH_TOKEN`; the
workflow supplies a run-scoped, non-secret lab value built from the run ID. No
repository secret is required.

Stage 3 is still read-only and uses the same scope, rate limits, approval gate,
and evidence store as every other Anbu run.

## Reproduce locally

With Ollama running on the host and the model pulled:

```powershell
$env:OLLAMA_MODEL = "dolphin3:8b"
$env:OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"
$env:ANBU_AUTH_TOKEN = "local-lab-token"

npm run build
node dist/index.js doctor
node dist/index.js ask "Reply with exactly the two letters OK and nothing else."

docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 `
  bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809
node dist/index.js intake --scope scope/ci-juice-shop.json
node dist/index.js pentest --scope scope/ci-juice-shop.json --no-model --json
node dist/index.js pentest --scope scope/ci-juice-shop.json --json
```

The deterministic pentest does not need Ollama, so it also works on a machine
that cannot run the model. The final command is the experimental stage and may
take several minutes or hit the planner timeout on slow CPU hardware.

## Limitations

- A hosted runner has no GPU. Expect the first model call to spend most of its
  time loading the 4.9 GB model into RAM; the benchmark reports that separately.
- Stage 3 is experimental: the SDK allows 300 seconds per planner request, and
  a slow CPU runner can exceed it. The stage records the failure without failing
  the job.
- The model artifact is downloaded on every run because it exceeds practical
  GitHub Actions cache limits. A weekly schedule keeps that cost bounded.
- The workflow performs no state-changing tests and keeps the same read-only,
  scope, rate-limit, and evidence guardrails as every other Anbu run.
