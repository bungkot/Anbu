import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEntry } from "../../../src/audit/log.js";
import { AuditLog } from "../../../src/audit/log.js";
import type { ApprovalProvider, ApprovalRequest } from "../../../src/agent/approval.js";
import type { BudgetLimits } from "../../../src/agent/budget.js";
import { resolveBudgetLimits } from "../../../src/agent/budget.js";
import { RunContext } from "../../../src/agent/context.js";
import type { PlannerTransport, PlannerTextResult } from "../../../src/agent/planner.js";
import type { Finding } from "../../../src/model/finding.js";
import type { Scope } from "../../../src/model/scope.js";
import { RateLimiter } from "../../../src/guardrails/rate-limit.js";
import { EvidenceStore } from "../../../src/store/evidence-store.js";
import { GuardedHttpClient } from "../../../src/tools/http.js";
import { makeFinding } from "../../../src/tools/checks/types.js";
import { sqliCheck } from "../../../src/tools/checks/sqli.js";
import { makeScope } from "../helpers.js";

/** Write a scope document to a temp file and return its path. */
export async function writeScope(value: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-agent-"));
  const path = join(dir, "scope.json");
  await writeFile(path, JSON.stringify(value), "utf8");
  return path;
}

/**
 * A scope tuned for agent-loop tests: read-only, high per-host rate limit so the
 * suite never waits on throttling, and a request budget large enough for the
 * deterministic baseline.
 */
export function loopScope(overrides: Partial<Scope> = {}): Scope {
  return makeScope({
    readOnly: true,
    policy: { requestsPerSecondPerHost: 1000, maxRequests: 800 },
    ...overrides,
  });
}

/** Scripted planner transport: records prompts, replays responses in order. */
export class FakePlannerTransport implements PlannerTransport {
  readonly requests: Array<{ system: string; user: string }> = [];
  private readonly responses: string[];
  private index = 0;
  private startedFlag = false;
  private stoppedFlag = false;
  startError?: Error;

  constructor(responses: string[] = []) {
    this.responses = responses;
  }

  get started(): boolean {
    return this.startedFlag;
  }

  get stopped(): boolean {
    return this.stoppedFlag;
  }

  async start(): Promise<void> {
    if (this.startError !== undefined) throw this.startError;
    this.startedFlag = true;
  }

  async stop(): Promise<void> {
    this.stoppedFlag = true;
  }

  async request(system: string, user: string): Promise<PlannerTextResult> {
    this.requests.push({ system, user });
    if (this.responses.length === 0) return { ok: false, error: "no scripted response" };
    const text = this.responses[Math.min(this.index, this.responses.length - 1)];
    this.index += 1;
    return { ok: true, text };
  }
}

export interface RecordingApproval {
  provider: ApprovalProvider;
  requests: ApprovalRequest[];
}

/** Approval provider that records every request and returns a fixed decision. */
export function makeRecordingApproval(granted = false): RecordingApproval {
  const requests: ApprovalRequest[] = [];
  return {
    requests,
    provider: {
      async approve(request: ApprovalRequest): Promise<boolean> {
        requests.push(request);
        return granted;
      },
    },
  };
}

export interface RecordedFetch {
  url: string;
  method: string;
}

export interface FetchFnOptions {
  /** Optional response handler; defaults to a small HTML page with a search link. */
  handler?: (url: string, init?: RequestInit) => Response | Promise<Response>;
}

/** Fake global fetch that records every outbound call. */
export function makeFetchFn(options: FetchFnOptions = {}): {
  fetchFn: typeof fetch;
  calls: RecordedFetch[];
} {
  const calls: RecordedFetch[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    let url: string;
    let method: string;
    if (typeof input === "string") {
      url = input;
      method = init?.method ?? "GET";
    } else if (input instanceof URL) {
      url = input.toString();
      method = init?.method ?? "GET";
    } else {
      url = input.url;
      method = input.method;
    }
    calls.push({ url, method });
    if (options.handler !== undefined) return options.handler(url, init);
    return new Response('<html><body><a href="/search?q=1">search</a></body></html>', {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };
  return { fetchFn, calls };
}

/** Read and parse the hash-chained audit log written by a pentest run. */
export async function readAuditLines(dir: string, runId: string): Promise<AuditEntry[]> {
  const text = await readFile(join(dir, runId, "audit.log"), "utf8");
  return text
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as AuditEntry);
}

/** Build a real RunContext with temp evidence storage and a fake HTTP backend. */
export async function makeRunContext(
  options: {
    scope?: Scope;
    limits?: Partial<BudgetLimits>;
    fetchFn?: typeof fetch;
    env?: (name: string) => string | undefined;
  } = {},
): Promise<{ ctx: RunContext; dir: string }> {
  const scope = options.scope ?? makeScope();
  const dir = await mkdtemp(join(tmpdir(), "anbu-agent-ctx-"));
  const audit = new AuditLog(join(dir, "audit.log"), "run-context-test");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: 1000,
    maxRequests: 10_000,
  });
  const store = new EvidenceStore({ rootDir: dir });
  const client = new GuardedHttpClient({
    scope,
    rateLimiter,
    audit,
    fetchFn: options.fetchFn ?? (async () => new Response("<html></html>")),
    env: options.env,
  });
  const limits: BudgetLimits = { ...resolveBudgetLimits(scope), ...options.limits };
  const ctx = new RunContext({
    runId: "run",
    scope,
    limits,
    rateLimiter,
    audit,
    store,
    client,
  });
  return { ctx, dir };
}

/** A minimal, well-formed finding for context and cap tests. */
export function makeTestFinding(title: string): Finding {
  return makeFinding(sqliCheck.metadata, {
    title,
    affected: { url: "https://example.test/search?q=1", parameter: "q" },
    reproduction: ["Replay the captured request against the target"],
    remediation: "Use parameterized queries and validate input",
  });
}
