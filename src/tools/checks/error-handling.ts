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
  readOptionString,
  withQuery,
} from "./util.js";

const ERROR_SIGNATURES: readonly RegExp[] = [
  /\bat\s+[\w$.]+\s*\([^)]*:\d+:\d+\)/,
  /Exception in thread/,
  /Stack Trace/i,
  /Traceback \(most recent call last\)/,
  /Fatal error/i,
  /Uncaught Exception/i,
  /\/var\/www\//,
  /C:\\inetpub\\/i,
  /\/home\/[^/]+\//,
  /\/usr\/share\//,
  /SQL syntax/i,
  /Whoops/i,
  /\bLaravel\b/i,
  /\bDjango\b/i,
  /debug mode/i,
  /verbose error/i,
];

const ERROR_PAYLOADS: readonly string[] = [
  '{"bad":',
  "<bad",
  "'%00",
  "../../",
  "999999999999999999999999999999",
  "true;false",
];

export interface ErrorHandlingProbe {
  payload: string;
  response: CheckResponse;
}

export interface ErrorHandlingObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: ErrorHandlingProbe[];
}

/**
 * Pure analyzer: detect stack traces, absolute file paths, framework debug
 * pages, and SQL errors in responses to malformed input. Signatures already
 * present in the baseline are ignored.
 */
export function analyzeErrorHandling(observation: ErrorHandlingObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineBody = observation.baseline.bodyText;
  const seen = new Set<string>();

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    for (const pattern of ERROR_SIGNATURES) {
      const match = pattern.exec(body);
      if (match === null) continue;
      if (pattern.test(baselineBody)) continue;
      const key = `${probe.payload}\u0000${pattern.source}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        title: "Detailed error information disclosed to the client",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "medium",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
        ],
        remediation:
          "Return generic error messages to clients, log detail server-side, and disable framework debug modes in production.",
        details: `The response disclosed "${match[0].slice(0, 80)}".`,
        falsePositiveAnalysis:
          "The signature appears only after malformed input and is absent from the baseline response.",
      });
      break;
    }
  }

  return findings;
}

/** Server software/version headers that aid fingerprinting. */
export function analyzeServerVersionHeaders(response: CheckResponse): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const server = headerValue(response.headers, "server");
  const poweredBy = headerValue(response.headers, "x-powered-by");
  if (server !== undefined && /\d+\.\d+/.test(server)) {
    findings.push({
      title: "Server header discloses software version",
      affected: { url: response.url },
      severity: "low",
      reproduction: [`Send GET ${response.url} and inspect the Server header.`],
      remediation: "Suppress or genericize the Server and X-Powered-By headers.",
      details: `Server: ${server}`,
    });
  }
  if (poweredBy !== undefined && /\d+\.\d+/.test(poweredBy)) {
    findings.push({
      title: "X-Powered-By header discloses framework version",
      affected: { url: response.url },
      severity: "low",
      reproduction: [`Send GET ${response.url} and inspect the X-Powered-By header.`],
      remediation: "Remove the X-Powered-By header or replace it with a generic value.",
      details: `X-Powered-By: ${poweredBy}`,
    });
  }
  return findings;
}

export const errorHandlingCheck: Check = {
  metadata: {
    id: "error-handling",
    toolName: "check_error_handling",
    title: "Error handling and information disclosure",
    description:
      "Forces safe error conditions and inspects messages for stack traces, paths, and framework debug data.",
    category: "A10",
    categories: ["A10"],
    cwe: "CWE-209",
    relatedCwes: ["CWE-754", "CWE-538"],
    readOnly: true,
    requiresApproval: false,
    severity: "medium",
    maxRequests: ERROR_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/",
      "https://cwe.mitre.org/data/definitions/209.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(ctx, [], [], undefined, "error-handling check requires a parameter name");
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "error-handling check received no response");
    }

    const probes: ErrorHandlingProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of ERROR_PAYLOADS) {
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
    const candidates = [
      ...analyzeErrorHandling({
        url: input.url,
        parameter,
        baseline: primary.response,
        probes,
      }),
      ...analyzeServerVersionHeaders(primary.response),
    ];
    return checkResult(ctx, materialize(errorHandlingCheck.metadata, candidates, evidence), evidence);
  },
};
