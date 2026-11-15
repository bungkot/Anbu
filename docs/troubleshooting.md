# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Refusing to start: authorization` | Scope missing, expired, or token unresolved | Check `scope/example.json` (or your scope file), validity window, and `ANBU_AUTH_TOKEN`. |
| `Refusing to start: no targets` | Empty `targets` array or all denied | Add an allowed target and path. |
| `Request blocked: out of scope` | Host/path/port/method not in `targets`, or matched `deny` | Fix the URL or update the scope; deny always wins. |
| `Request blocked: rate limit` | Per-host pacing waited out (`ANBU_RATE_LIMIT_WAIT_MS`) or the global budget is exhausted | Raise `ANBU_RATE_LIMIT_WAIT_MS`, lower `ANBU_REQUESTS_PER_SECOND_PER_HOST`, or raise the request budget. |
| `Ollama is not responding` | Stack not running or wrong base URL | `docker compose up -d`; run `npm run doctor`. |
| `Model is not available` | Model not pulled | `docker compose exec ollama ollama pull <model>`. |
| LLM returns invalid JSON | Model too small or prompt too long | Use a larger model, shorten context, or rely on deterministic checks. |
| Target response hangs | Proxy blocking SSE/streaming, or slow model | Access Ollama directly; check `docker stats`; raise timeouts. |
| Too many false positives | Weak payloads or missing baseline | Compare against baseline; tune/disable the check; raise confidence threshold. |
| No findings on a vulnerable fixture | Check not implemented or category out of scope | Confirm `testClasses`; run the check's unit tests. |
| Evidence directory grows quickly | Large bodies or many requests | Lower `maxBodyBytes` and `maxRequests`; prune old runs. |
| `docker: dubious ownership` in dev container | Mount UID mismatch | Already handled via `safe.directory` in the Dockerfile. |
| Port 4096 in use | Another OpenCode server | Set `OPENCODE_PORT` or stop the other server. |

## Getting help

1. Run `npm run doctor` and include the output.
2. Re-run the failing command with debug logging enabled.
3. Check the audit log for guardrail decisions.
4. Include the run ID, scope reference (not the token), and finding ID when
   reporting an issue.
