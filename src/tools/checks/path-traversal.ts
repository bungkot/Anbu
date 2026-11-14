import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import { captureAll, fetchPrimary, materialize, readOptionString, withQuery } from "./util.js";

/** File-content signatures that indicate a successful traversal. */
const TRAVERSAL_SIGNATURES: readonly RegExp[] = [
  /root:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*/,
  /\[boot loader\]/i,
  /\[operating systems\]/i,
  /<\?php/i,
  /^\s*namespace\s+\S+/m,
  /^\s*\[extensions\]\s*$/im,
];

const TRAVERSAL_PAYLOADS: readonly string[] = [
  "../../../../etc/passwd",
  "..%2f..%2f..%2f..%2fetc%2fpasswd",
  "....//....//....//etc//passwd",
  "../../../../etc/passwd%00",
  "file:///etc/passwd",
  "../../../../windows/win.ini",
];

export interface PathTraversalProbe {
  payload: string;
  response: CheckResponse;
}

export interface PathTraversalObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: PathTraversalProbe[];
}

/**
 * Pure analyzer: report a traversal only when a known file signature appears in
 * a probe response and is absent from the baseline.
 */
export function analyzePathTraversal(observation: PathTraversalObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineBody = observation.baseline.bodyText;

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    for (const pattern of TRAVERSAL_SIGNATURES) {
      const match = pattern.exec(body);
      if (match === null) continue;
      if (pattern.test(baselineBody)) continue;
      findings.push({
        title: "Path traversal returned protected file content",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
        ],
        remediation:
          "Resolve user-supplied paths against a fixed base directory, normalize and canonicalize them, and reject any path that escapes the base.",
        details: `Payload ${probe.payload} produced file content matching "${match[0].slice(0, 60)}".`,
        falsePositiveAnalysis:
          "The matched content is a protected file signature that was absent from the baseline response.",
      });
      break;
    }
  }

  return findings;
}

export const pathTraversalCheck: Check = {
  metadata: {
    id: "path-traversal",
    toolName: "check_path_traversal",
    title: "Path traversal probes",
    description:
      "Tests file/path parameters with traversal sequences and detects protected file content in the response.",
    category: "A01",
    categories: ["A01", "A05"],
    cwe: "CWE-22",
    relatedCwes: ["CWE-23", "CWE-35"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: TRAVERSAL_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/22.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(ctx, [], [], undefined, "path-traversal check requires a parameter name");
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "path-traversal check received no response");
    }

    const probes: PathTraversalProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of TRAVERSAL_PAYLOADS) {
      const result = await ctx.fetch({
        method: "GET",
        url: withQuery(input.url, parameter, payload),
        headers: input.headers,
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ payload, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzePathTraversal({
      url: input.url,
      parameter,
      baseline: primary.response,
      probes,
    });
    return checkResult(
      ctx,
      materialize(pathTraversalCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
