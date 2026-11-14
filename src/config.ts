/** Centralized configuration, read from environment variables. */
export const config = {
  /** Ollama's OpenAI-compatible endpoint (ends with /v1). */
  ollamaBaseUrl: process.env.OLLAMA_BASE_URL ?? "http://localhost:11434/v1",
  /** Ollama model name, e.g. granite3.3:2b */
  model: process.env.OLLAMA_MODEL ?? "granite3.3:2b",
  opencodeHost: process.env.OPENCODE_HOST ?? "127.0.0.1",
  opencodePort: Number(process.env.OPENCODE_PORT ?? 4096),

  /** Scope document for the run. The engine refuses to start without it. */
  scopeFile: process.env.ANBU_SCOPE_FILE ?? "",
  /** Evidence output directory (kept outside the repository by default). */
  evidenceDir: process.env.ANBU_EVIDENCE_DIR ?? "workspace/evidence",
  /** Authorization token referenced by the scope document. Never logged. */
  authToken: process.env.ANBU_AUTH_TOKEN ?? "",
  /** Default runtime budgets (overridable in the scope document). */
  maxRequests: Number(process.env.ANBU_MAX_REQUESTS ?? 800),
  maxDurationMinutes: Number(process.env.ANBU_MAX_DURATION_MINUTES ?? 60),
  requestsPerSecondPerHost: Number(process.env.ANBU_REQUESTS_PER_SECOND_PER_HOST ?? 5),
  /** Read-only by default. State-changing tests require explicit approval. */
  readOnly: (process.env.ANBU_READ_ONLY ?? "true") === "true",
} as const;

/**
 * Read an environment variable by name. This is the only module allowed to
 * touch `process.env`, so tests can substitute their own resolver.
 */
export function readEnv(name: string): string | undefined {
  return process.env[name];
}

/** Ollama root without the /v1 suffix, for the native API (/api/tags). */
export function ollamaRoot(): string {
  return config.ollamaBaseUrl.replace(/\/v1\/?$/, "");
}
