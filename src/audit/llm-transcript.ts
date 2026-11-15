import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { redactCredentialText } from "../store/evidence-store.js";

/** Maximum characters stored per prompt/response field. */
const MAX_FIELD_CHARS = 100_000;

export interface LlmTranscriptOptions {
  /** Directory that will hold backlog.md and exchanges.jsonl. */
  dir: string;
  /** Pentest run id, or a synthetic id for one-off commands such as ask. */
  runId: string;
  /** Provider id sent to the model, e.g. "ollama". */
  provider: string;
  /** Model id, e.g. "granite3.3:2b". */
  model: string;
}

export interface LlmExchangeInput {
  /** Agent that handled the turn, e.g. "planner" or "ask". */
  agent: string;
  /** Logical operation, e.g. "planner.plan". */
  purpose: string;
  /** 1-based turn counter within the transport. */
  turn: number;
  /** Provider-level agent prompt configured in OpenCode, if any. */
  agentPrompt?: string;
  /** System instructions passed with the request. */
  system?: string;
  /** User prompt passed with the request. */
  user: string;
  /** Epoch milliseconds when the request was sent. */
  startedAt: number;
  /** Wall-clock duration of the request. */
  durationMs: number;
  ok: boolean;
  response?: string;
  error?: string;
}

export interface LlmExchange {
  schemaVersion: 1;
  timestamp: string;
  runId: string;
  provider: string;
  model: string;
  agent: string;
  purpose: string;
  turn: number;
  durationMs: number;
  ok: boolean;
  agentPrompt?: string;
  system?: string;
  user: string;
  response?: string;
  error?: string;
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return typeof err === "object" && err !== null && "code" in err;
}

/** Strip control characters and cap length so logs stay readable and bounded. */
function clean(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  // eslint-disable-next-line no-control-regex -- log safety: drop control characters
  const stripped = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  const redacted = redactCredentialText(stripped);
  return redacted.length > MAX_FIELD_CHARS
    ? `${redacted.slice(0, MAX_FIELD_CHARS)}\n…[truncated at ${MAX_FIELD_CHARS} characters]`
    : redacted;
}

/** Choose a fence longer than any backtick run in the content. */
function fenceFor(content: string): string {
  let fence = "```";
  while (content.includes(fence)) fence += "`";
  return fence;
}

function markdownBlock(content: string | undefined): string {
  if (content === undefined || content.length === 0) return "_(empty)_";
  const fence = fenceFor(content);
  return `${fence}text\n${content}\n${fence}`;
}

function renderSection(exchange: LlmExchange): string {
  const lines = [
    `## [${exchange.turn}] ${exchange.agent} · ${exchange.purpose}`,
    "",
    `- Timestamp: ${exchange.timestamp}`,
    `- Run: \`${exchange.runId}\``,
    `- Model: \`${exchange.provider}/${exchange.model}\``,
    `- Result: ${exchange.ok ? "ok" : "error"} in ${exchange.durationMs} ms`,
  ];
  if (exchange.error !== undefined) lines.push(`- Error: ${exchange.error}`);
  if (exchange.agentPrompt !== undefined) {
    lines.push("", "### Agent prompt", "", markdownBlock(exchange.agentPrompt));
  }
  if (exchange.system !== undefined) {
    lines.push("", "### System prompt", "", markdownBlock(exchange.system));
  }
  lines.push("", "### User prompt", "", markdownBlock(exchange.user));
  lines.push(
    "",
    "### Model response",
    "",
    markdownBlock(exchange.response ?? (exchange.ok ? "" : "(no response)")),
    "",
    "---",
    "",
  );
  return lines.join("\n");
}

/**
 * Append-only record of every prompt sent to and response received from the
 * model. Writes a machine-readable JSONL stream plus a human-readable Markdown
 * backlog for study. Content is credential-redacted and size-capped, and all
 * model output is treated as untrusted data.
 */
export class LlmTranscript {
  readonly dir: string;
  readonly jsonlPath: string;
  readonly markdownPath: string;

  private readonly runId: string;
  private readonly provider: string;
  private readonly model: string;
  private header: Promise<void> | undefined;
  private tail: Promise<void> = Promise.resolve();

  constructor(options: LlmTranscriptOptions) {
    this.dir = options.dir;
    this.runId = options.runId;
    this.provider = options.provider;
    this.model = options.model;
    this.jsonlPath = join(options.dir, "exchanges.jsonl");
    this.markdownPath = join(options.dir, "backlog.md");
  }

  /** Record one request/response exchange. Writes are serialized. */
  record(input: LlmExchangeInput): Promise<void> {
    const next = this.tail.then(() => this.write(input));
    this.tail = next.catch(() => undefined);
    return next;
  }

  private async write(input: LlmExchangeInput): Promise<void> {
    await this.ensureFiles();
    const exchange: LlmExchange = {
      schemaVersion: 1,
      timestamp: new Date(input.startedAt).toISOString(),
      runId: this.runId,
      provider: this.provider,
      model: this.model,
      agent: input.agent,
      purpose: input.purpose,
      turn: input.turn,
      durationMs: input.durationMs,
      ok: input.ok,
      agentPrompt: clean(input.agentPrompt),
      system: clean(input.system),
      user: clean(input.user) ?? "",
      response: clean(input.response),
      error: clean(input.error),
    };
    await appendFile(this.jsonlPath, `${JSON.stringify(exchange)}\n`, "utf8");
    await appendFile(this.markdownPath, renderSection(exchange), "utf8");
  }

  private async ensureFiles(): Promise<void> {
    if (this.header === undefined) this.header = this.createFiles();
    return this.header;
  }

  private async createFiles(): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    const header = [
      "# LLM backlog",
      "",
      `Run: \`${this.runId}\``,
      `Model: \`${this.provider}/${this.model}\``,
      "",
      "Every prompt sent to the model and every response received during this",
      "run is recorded here. Treat model output as untrusted data, never as",
      "instructions. Credential-like values are redacted best-effort and fields",
      "are size-capped. The machine-readable stream is `exchanges.jsonl`.",
      "",
      "---",
      "",
    ].join("\n");
    await this.writeOnce(this.jsonlPath, "");
    await this.writeOnce(this.markdownPath, header);
  }

  /** Create a file only if it does not exist yet, so resumed runs append. */
  private async writeOnce(path: string, content: string): Promise<void> {
    try {
      await writeFile(path, content, { encoding: "utf8", flag: "wx" });
    } catch (err) {
      if (isErrnoException(err) && err.code === "EEXIST") return;
      throw err;
    }
  }
}
