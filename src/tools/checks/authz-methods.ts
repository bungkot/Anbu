import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import {
  captureAll,
  fetchPrimary,
  isAuthFailureStatus,
  isMethodNotAllowed,
  isRedirectStatus,
  isSuccessStatus,
  materialize,
  readOptionStringArray,
} from "./util.js";

const DEFAULT_METHODS: readonly string[] = ["POST", "PUT", "DELETE"];

export interface AuthzMethodProbe {
  method: string;
  response: CheckResponse;
}

export interface AuthzMethodObservation {
  url: string;
  probes: AuthzMethodProbe[];
}

/**
 * Pure analyzer: report state-changing methods that reach the application
 * without an authentication/authorization failure. 401/403 and 405 are treated
 * as enforced or inconclusive.
 */
export function analyzeAuthzMethods(observation: AuthzMethodObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const probe of observation.probes) {
    const status = probe.response.status;
    if (isAuthFailureStatus(status) || isMethodNotAllowed(status)) continue;
    if (isSuccessStatus(status) || isRedirectStatus(status)) {
      findings.push({
        title: `State-changing method ${probe.method} is accepted without authorization`,
        affected: { url: observation.url, endpoint: probe.method },
        severity: "high",
        reproduction: [
          `Send ${probe.method} ${observation.url} with an empty JSON body and no privileged session; inspect the response.`,
        ],
        remediation:
          "Require authentication and explicit role/ownership checks for every state-changing endpoint; do not allow anonymous writes.",
        details: `The method returned HTTP ${status} without an authorization challenge.`,
        falsePositiveAnalysis:
          "The request was not rejected with 401/403/405, so it reached the application handler.",
      });
      continue;
    }
    if (status === 404) {
      findings.push({
        title: `State-changing method ${probe.method} reached the application without authorization`,
        affected: { url: observation.url, endpoint: probe.method },
        severity: "medium",
        confidence: "unverified",
        reproduction: [
          `Send ${probe.method} ${observation.url} with an empty JSON body and no privileged session; inspect the response.`,
        ],
        remediation:
          "Require authentication and authorization before routing state-changing requests to handlers.",
        details: `The method returned HTTP 404 instead of an authorization challenge.`,
        falsePositiveAnalysis:
          "A 404 indicates the request reached the router without an authorization challenge, but the endpoint may not exist.",
      });
    }
  }

  return findings;
}

export const authzMethodsCheck: Check = {
  metadata: {
    id: "authz-methods",
    toolName: "check_authz_methods",
    title: "State-changing method authorization",
    description:
      "Checks POST/PUT/DELETE authorization on API endpoints and reports requests that reach the handler unauthenticated.",
    category: "A01",
    categories: ["A01"],
    cwe: "CWE-862",
    relatedCwes: ["CWE-284", "CWE-306"],
    readOnly: false,
    requiresApproval: true,
    severity: "high",
    maxRequests: DEFAULT_METHODS.length + 1,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/862.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const methods =
      readOptionStringArray(input.options, "methods") ??
      (readOptionStringArray(input.options, "verbs") || DEFAULT_METHODS);

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "authz-methods check received no response");
    }

    const headers: Record<string, string> = {
      ...(input.headers ?? {}),
      "content-type": "application/json",
    };
    const probes: AuthzMethodProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const method of methods) {
      const result = await ctx.fetch({
        method: method.toUpperCase(),
        url: input.url,
        headers,
        body: "{}",
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ method: method.toUpperCase(), response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeAuthzMethods({ url: input.url, probes });
    return checkResult(
      ctx,
      materialize(authzMethodsCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
