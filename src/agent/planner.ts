import { config } from "../config.js";
import type { OwaspCategory } from "../model/scope.js";
import { startOpencode } from "../opencode.js";
import { getCheck } from "../tools/checks/index.js";
import type { CheckInput } from "../tools/checks/types.js";
import type { HttpRequestInput } from "../tools/http.js";

/** Closed action schema. The planner cannot invent kinds or checks. */
export type PlannerAction =
  | { kind: "run_check"; checkId: string; input: CheckInput }
  | { kind: "http_request"; input: HttpRequestInput }
  | { kind: "halt"; reason: string };

export interface PlannerPlan {
  objective: string;
  actions: PlannerAction[];
  rationale?: string;
}

export type PlannerResult = { ok: true; plan: PlannerPlan } | { ok: false; error: string };

export type PlannerTextResult = { ok: true; text: string } | { ok: false; error: string };

/** Transport abstraction so the loop can be tested without a live model. */
export interface PlannerTransport {
  start(): Promise<void>;
  stop(): Promise<void>;
  request(system: string, user: string): Promise<PlannerTextResult>;
}

export interface PlannerOptions {
  transport: PlannerTransport;
  maxActionsPerPlan: number;
  allowedCategories?: ReadonlySet<OwaspCategory>;
}

/** Turns one planner turn into a validated plan. */
export class Planner {
  private readonly transport: PlannerTransport;
  private readonly maxActionsPerPlan: number;
  private readonly allowedCategories: ReadonlySet<OwaspCategory> | undefined;

  constructor(options: PlannerOptions) {
    this.transport = options.transport;
    this.maxActionsPerPlan = options.maxActionsPerPlan;
    this.allowedCategories = options.allowedCategories;
  }

  async plan(system: string, user: string): Promise<PlannerResult> {
    const response = await this.transport.request(system, user);
    if (!response.ok) return { ok: false, error: response.error };
    return parsePlannerResponse(response.text, {
      maxActions: this.maxActionsPerPlan,
      allowedCategories: this.allowedCategories,
    });
  }
}

export interface ParseOptions {
  maxActions: number;
  allowedCategories?: ReadonlySet<OwaspCategory>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Extract the first JSON object from a model response, tolerating code fences. */
function extractJsonObject(text: string): string | undefined {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return undefined;
  return text.slice(start, end + 1);
}

function parseStringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") return undefined;
    out[key] = item;
  }
  return out;
}

function parseCheckInput(value: unknown): { ok: true; input: CheckInput } | { ok: false; error: string } {
  if (!isRecord(value)) return { ok: false, error: "must be an object" };
  if (typeof value.url !== "string" || value.url.length === 0) {
    return { ok: false, error: "url must be a non-empty string" };
  }
  const input: CheckInput = { url: value.url };
  if (typeof value.method === "string" && value.method.length > 0) input.method = value.method;
  if (typeof value.parameter === "string" && value.parameter.length > 0) {
    input.parameter = value.parameter;
  }
  if (typeof value.body === "string") input.body = value.body;
  const headers = parseStringRecord(value.headers);
  if (headers !== undefined) input.headers = headers;
  if (isRecord(value.options)) input.options = value.options;
  if (typeof value.evidenceId === "string" && value.evidenceId.length > 0) {
    input.evidenceId = value.evidenceId;
  }
  return { ok: true, input };
}

function parseHttpRequestInput(
  value: unknown,
): { ok: true; input: HttpRequestInput } | { ok: false; error: string } {
  if (!isRecord(value)) return { ok: false, error: "must be an object" };
  if (typeof value.url !== "string" || value.url.length === 0) {
    return { ok: false, error: "url must be a non-empty string" };
  }
  const input: HttpRequestInput = {
    method: typeof value.method === "string" && value.method.length > 0 ? value.method : "GET",
    url: value.url,
  };
  if (typeof value.body === "string") input.body = value.body;
  const headers = parseStringRecord(value.headers);
  if (headers !== undefined) input.headers = headers;
  return { ok: true, input };
}

type ParsedAction = { ok: true; action: PlannerAction } | { ok: false; error: string };

function parseAction(value: unknown, allowedCategories?: ReadonlySet<OwaspCategory>): ParsedAction {
  if (!isRecord(value)) return { ok: false, error: "must be an object" };
  const kind = value.kind;

  if (kind === "halt") {
    const reason = typeof value.reason === "string" ? value.reason : "planner requested halt";
    return { ok: true, action: { kind: "halt", reason } };
  }

  if (kind === "run_check") {
    if (typeof value.checkId !== "string" || value.checkId.length === 0) {
      return { ok: false, error: "run_check requires a checkId" };
    }
    const check = getCheck(value.checkId);
    if (check === undefined) return { ok: false, error: `unknown check: ${value.checkId}` };
    if (
      allowedCategories !== undefined &&
      !check.metadata.categories.some((category) => allowedCategories.has(category))
    ) {
      return { ok: false, error: `check ${value.checkId} is outside the in-scope test classes` };
    }
    const input = parseCheckInput(value.input);
    if (!input.ok) return { ok: false, error: `run_check input: ${input.error}` };
    return { ok: true, action: { kind: "run_check", checkId: value.checkId, input: input.input } };
  }

  if (kind === "http_request") {
    const input = parseHttpRequestInput(value.input);
    if (!input.ok) return { ok: false, error: `http_request input: ${input.error}` };
    return { ok: true, action: { kind: "http_request", input: input.input } };
  }

  return { ok: false, error: `unknown action kind: ${String(kind)}` };
}

/** Strict parse of the planner response. Unknown fields are ignored. */
export function parsePlannerResponse(text: string, options: ParseOptions): PlannerResult {
  const json = extractJsonObject(text);
  if (json === undefined) return { ok: false, error: "planner response did not contain a JSON object" };

  let value: unknown;
  try {
    value = JSON.parse(json) as unknown;
  } catch {
    return { ok: false, error: "planner response is not valid JSON" };
  }
  if (!isRecord(value)) return { ok: false, error: "planner response must be a JSON object" };

  const rawActions = value.actions;
  if (!Array.isArray(rawActions)) {
    return { ok: false, error: "planner response must include an actions array" };
  }
  if (rawActions.length > options.maxActions) {
    return {
      ok: false,
      error: `planner returned ${rawActions.length} actions, exceeding the limit of ${options.maxActions}`,
    };
  }

  const actions: PlannerAction[] = [];
  for (let i = 0; i < rawActions.length; i++) {
    const parsed = parseAction(rawActions[i], options.allowedCategories);
    if (!parsed.ok) return { ok: false, error: `action[${i}]: ${parsed.error}` };
    actions.push(parsed.action);
  }

  return {
    ok: true,
    plan: {
      objective: typeof value.objective === "string" ? value.objective : "",
      actions,
      rationale: typeof value.rationale === "string" ? value.rationale : undefined,
    },
  };
}

/**
 * Planner transport backed by the embedded OpenCode server and the local Ollama
 * model. One server and session are reused for every planner turn of a run.
 */
export class OpenCodePlannerTransport implements PlannerTransport {
  private handle: Awaited<ReturnType<typeof startOpencode>> | undefined;
  private sessionId: string | undefined;

  async start(): Promise<void> {
    if (this.handle !== undefined) return;
    this.handle = await startOpencode();
    const session = await this.handle.client.session.create({ body: { title: "pentest-planner" } });
    if (!session.data) {
      this.handle.server.close();
      this.handle = undefined;
      throw new Error(`failed to create planner session: ${JSON.stringify(session.error)}`);
    }
    this.sessionId = session.data.id;
  }

  async stop(): Promise<void> {
    if (this.handle === undefined) return;
    this.handle.server.close();
    this.handle = undefined;
    this.sessionId = undefined;
  }

  async request(system: string, user: string): Promise<PlannerTextResult> {
    if (this.handle === undefined || this.sessionId === undefined) {
      return { ok: false, error: "planner transport is not started" };
    }
    try {
      const result = await this.handle.client.session.prompt({
        path: { id: this.sessionId },
        body: {
          model: { providerID: "ollama", modelID: config.model },
          agent: "planner",
          tools: { "*": false },
          parts: [{ type: "text", text: `${system}\n\n${user}` }],
        },
      });
      if (!result.data) {
        return { ok: false, error: `planner prompt failed: ${JSON.stringify(result.error)}` };
      }
      const text = result.data.parts
        .filter((part) => part.type === "text")
        .map((part) => part.text)
        .join("\n")
        .trim();
      if (text.length === 0) return { ok: false, error: "planner returned an empty response" };
      return { ok: true, text };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
}
