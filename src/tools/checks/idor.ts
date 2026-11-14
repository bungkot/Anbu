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
  isAuthFailureStatus,
  isSuccessStatus,
  materialize,
  readOptionString,
  readOptionStringArray,
  withQuery,
} from "./util.js";

const OBJECT_MARKERS: readonly RegExp[] = [
  /"email"\s*:/i,
  /"username"\s*:/i,
  /"user(?:Id|Name|Role)"\s*:/i,
  /"account"\s*:/i,
  /"order(?:Id|Number)"\s*:/i,
  /"address"\s*:/i,
  /"phone"\s*:/i,
];

export interface IdorProbe {
  value: string;
  response: CheckResponse;
}

export interface IdorObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: IdorProbe[];
}

/** Derive adjacent numeric object ids when the caller does not supply any. */
export function deriveAlternates(url: string, parameter: string): string[] | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  const value = parsed.searchParams.get(parameter);
  if (value === null || value.length === 0) return undefined;
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric === 0) return undefined;
  return [String(numeric - 1), String(numeric + 1)];
}

/**
 * Pure analyzer: report when an alternate object id returns another user's
 * object, or when an id that was forbidden for the baseline becomes readable.
 */
export function analyzeIdor(observation: IdorObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineStatus = observation.baseline.status;
  const baselineBody = observation.baseline.bodyText;

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    const status = probe.response.status;

    if (isSuccessStatus(status) && isAuthFailureStatus(baselineStatus)) {
      findings.push({
        title: "Direct object reference became accessible with an alternate id",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.value} using the same session and inspect the response.`,
        ],
        remediation:
          "Authorize every object lookup against the authenticated user's ownership; never rely on sequential or predictable ids.",
        details: `The baseline returned HTTP ${baselineStatus} while ${probe.value} returned HTTP ${status}.`,
        falsePositiveAnalysis:
          "The same session could not read the baseline object but could read the alternate object, so access control is inconsistent.",
      });
      continue;
    }

    if (!isSuccessStatus(status) || body.length === 0) continue;
    if (body === baselineBody) continue;
    if (!OBJECT_MARKERS.some((pattern) => pattern.test(body))) continue;
    if (baselineBody.includes(probe.value) && body.includes(probe.value) && body === baselineBody) {
      continue;
    }
    findings.push({
      title: "Direct object reference exposes another user's object",
      affected: { url: observation.url, parameter: observation.parameter },
      severity: "high",
      reproduction: [
        `Send GET ${observation.url} with ${observation.parameter}=${probe.value} using the same session and inspect the response.`,
      ],
      remediation:
        "Authorize every object lookup against the authenticated user's ownership and return the same response for objects the user may not access.",
      details: `The response for ${probe.value} contains user/object fields that differ from the baseline.`,
      falsePositiveAnalysis:
        "The response contains user-object markers and differs from the baseline while using the same session, indicating an object-level authorization gap.",
    });
  }

  return findings;
}

export const idorCheck: Check = {
  metadata: {
    id: "idor",
    toolName: "check_idor",
    title: "Insecure direct object reference probes",
    description:
      "Replays object access with alternate ids using the same session and compares the responses.",
    category: "A01",
    categories: ["A01"],
    cwe: "CWE-639",
    relatedCwes: ["CWE-284", "CWE-862"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 3,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/639.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(ctx, [], [], undefined, "idor check requires a parameter name");
    }
    const alternates =
      readOptionStringArray(input.options, "alternates") ??
      deriveAlternates(input.url, parameter);
    if (alternates === undefined || alternates.length === 0) {
      return checkResult(
        ctx,
        [],
        [],
        undefined,
        "idor check requires alternate ids (options.alternates or a numeric parameter)",
      );
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "idor check received no response");
    }

    const probes: IdorProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const value of alternates) {
      const result = await ctx.fetch({
        method: "GET",
        url: withQuery(input.url, parameter, value),
        headers: input.headers,
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ value, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeIdor({
      url: input.url,
      parameter,
      baseline: primary.response,
      probes,
    });
    return checkResult(ctx, materialize(idorCheck.metadata, candidates, evidence), evidence);
  },
};
