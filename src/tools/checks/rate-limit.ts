import type {
  CandidateFinding,
  Check,
  CheckResponse,
  CheckResult,
} from "./types.js";
import { checkResult } from "./types.js";
import {
  captureAll,
  fetchPrimary,
  headerValue,
  materialize,
  readOptionNumber,
} from "./util.js";

const DEFAULT_REQUESTS = 12;
const MINIMUM_SAMPLE = 8;

export interface RateLimitObservation {
  url: string;
  responses: CheckResponse[];
}

/**
 * Pure analyzer: report when a bounded burst of read-only requests is never
 * throttled and the server does not advertise a rate limit. A 429/503, a
 * Retry-After header, or a remaining-quota header is treated as enforcement.
 */
export function analyzeRateLimit(observation: RateLimitObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const responses = observation.responses;
  if (responses.length < MINIMUM_SAMPLE) return findings;

  const throttled = responses.some(
    (response) => response.status === 429 || response.status === 503,
  );
  const retryAfter = responses.some(
    (response) => headerValue(response.headers, "retry-after") !== undefined,
  );
  const quotaHeaders = responses.some(
    (response) =>
      headerValue(response.headers, "x-ratelimit-remaining") !== undefined ||
      headerValue(response.headers, "x-rate-limit-remaining") !== undefined ||
      headerValue(response.headers, "ratelimit-remaining") !== undefined,
  );

  if (throttled || retryAfter || quotaHeaders) return findings;

  findings.push({
    title: "No rate limiting observed on the endpoint",
    affected: { url: observation.url },
    severity: "medium",
    confidence: "unverified",
    reproduction: [
      `Send ${responses.length} read-only GET requests to ${observation.url} in a short burst and inspect the status codes and rate-limit headers.`,
    ],
    remediation:
      "Apply per-account and per-IP rate limiting to authentication, search, and other abusable endpoints; return 429 with Retry-After when the limit is exceeded.",
    details: `${responses.length} consecutive requests all returned HTTP 200 with no throttling or quota headers.`,
    falsePositiveAnalysis:
      "The burst was bounded and read-only; the absence of any throttle or quota header is a design gap rather than a confirmed exploit.",
  });

  return findings;
}

export const rateLimitCheck: Check = {
  metadata: {
    id: "rate-limit",
    toolName: "check_rate_limit",
    title: "Rate limiting behavior",
    description:
      "Sends a bounded burst of read-only requests and observes throttling behavior.",
    category: "A06",
    categories: ["A06", "A10"],
    cwe: "CWE-770",
    relatedCwes: ["CWE-799", "CWE-307"],
    readOnly: true,
    requiresApproval: false,
    severity: "medium",
    maxRequests: DEFAULT_REQUESTS + 1,
    references: [
      "https://owasp.org/Top10/A06_2025-Insecure_Design/",
      "https://cwe.mitre.org/data/definitions/770.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const requested = Math.max(
      1,
      Math.floor(readOptionNumber(input.options, "requests", DEFAULT_REQUESTS)),
    );
    const requestCount = Math.min(requested, rateLimitCheck.metadata.maxRequests - 1);

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "rate-limit check received no response");
    }

    const responses: CheckResponse[] = [primary.response];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (let i = 0; i < requestCount; i++) {
      const result = await ctx.fetch({
        method: "GET",
        url: input.url,
        headers: input.headers,
      });
      if (!result.ok || result.response === undefined) continue;
      responses.push(result.response);
      // Capture only the first and last responses to keep the evidence small.
      if (i === requestCount - 1) {
        pairs.push({ request: result.request, response: result.response });
      }
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeRateLimit({ url: input.url, responses });
    return checkResult(ctx, materialize(rateLimitCheck.metadata, candidates, evidence), evidence);
  },
};
