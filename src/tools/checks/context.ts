import type { AuditLog } from "../../audit/log.js";
import type { Scope } from "../../model/scope.js";
import type { EvidenceStore } from "../../store/evidence-store.js";
import type { GuardedHttpClient } from "../http.js";
import type {
  CheckCaptureRequest,
  CheckCaptureResponse,
  CheckContext,
  CheckFetchInput,
  CheckFetchResult,
} from "./types.js";
import { DEFAULT_CHECK_MAX_REQUESTS, toCheckResponse } from "./types.js";

export interface CheckContextOptions {
  scope: Scope;
  client: GuardedHttpClient;
  store: EvidenceStore;
  audit: AuditLog;
  now?: () => Date;
  maxRequests?: number;
}

/**
 * Build the runtime context for deterministic checks. The context owns the
 * per-run request budget and the evidence/audit bridges, so a check cannot
 * accidentally bypass the guardrail chain or write un-hashed artifacts.
 */
export function createCheckContext(options: CheckContextOptions): CheckContext {
  const now = options.now ?? (() => new Date());
  const ctx: CheckContext = {
    scope: options.scope,
    client: options.client,
    store: options.store,
    audit: options.audit,
    now,
    maxRequests: options.maxRequests ?? DEFAULT_CHECK_MAX_REQUESTS,
    requestCount: 0,
    async fetch(input: CheckFetchInput): Promise<CheckFetchResult> {
      if (ctx.requestCount >= ctx.maxRequests) {
        return {
          ok: false,
          request: input,
          error: `check request budget exhausted (${ctx.maxRequests} requests)`,
        };
      }
      ctx.requestCount += 1;
      const outcome = await options.client.request(input);
      if (!outcome.ok || outcome.response === undefined) {
        return {
          ok: false,
          request: input,
          error: outcome.error,
          requiresApproval: outcome.requiresApproval,
        };
      }
      return {
        ok: true,
        request: input,
        response: toCheckResponse(outcome.response, outcome.method),
      };
    },
    async capture(request: CheckCaptureRequest, response: CheckCaptureResponse) {
      const result = await options.store.capture({ request, response });
      if (!result.ok) return undefined;
      return { evidenceId: result.evidenceId, sha256: result.sha256, path: result.path };
    },
  };
  return ctx;
}
