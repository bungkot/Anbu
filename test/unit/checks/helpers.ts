import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../../src/audit/log.js";
import { RateLimiter } from "../../../src/guardrails/rate-limit.js";
import { EvidenceStore } from "../../../src/store/evidence-store.js";
import { GuardedHttpClient } from "../../../src/tools/http.js";
import { createCheckContext } from "../../../src/tools/checks/context.js";
import type { CheckContext, CheckResponse } from "../../../src/tools/checks/types.js";
import { makeScope } from "../helpers.js";

type TestScope = ReturnType<typeof makeScope>;

/** Build a real check context backed by a fake fetch and a temp evidence store. */
export async function makeCheckContext(options?: {
  scope?: TestScope;
  fetchFn?: typeof fetch;
  maxRequests?: number;
  now?: () => Date;
}): Promise<{
  ctx: CheckContext;
  audit: AuditLog;
  store: EvidenceStore;
  dir: string;
}> {
  const scope = options?.scope ?? makeScope();
  const dir = await mkdtemp(join(tmpdir(), "anbu-checks-"));
  const audit = new AuditLog(join(dir, "audit.log"), "run-check-test");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: 1000,
    maxRequests: 10_000,
  });
  const store = new EvidenceStore({ rootDir: dir });
  const client = new GuardedHttpClient({
    scope,
    rateLimiter,
    audit,
    fetchFn: options?.fetchFn,
    env: () => "test-token",
  });
  const ctx = createCheckContext({
    scope,
    client,
    store,
    audit,
    maxRequests: options?.maxRequests,
    now: options?.now,
  });
  return { ctx, audit, store, dir };
}

/** Build a normalized check response with per-test overrides. */
export function response(overrides: Partial<CheckResponse> = {}): CheckResponse {
  return {
    url: "https://example.test/page",
    method: "GET",
    status: 200,
    statusText: "OK",
    headers: {},
    bodyText: "",
    bodyBytes: 0,
    truncated: false,
    durationMs: 1,
    ...overrides,
  };
}
