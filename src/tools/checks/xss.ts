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
  materialize,
  readOptionString,
  withQuery,
} from "./util.js";

/** Unique marker reflected by the probes. It carries no executable payload. */
export const XSS_MARKER = "anbumarker";

export interface XssProbe {
  payload: string;
  response: CheckResponse;
}

export interface XssObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: XssProbe[];
}

const XSS_PAYLOADS: readonly string[] = [
  XSS_MARKER,
  `"><${XSS_MARKER}>`,
  `'<script>${XSS_MARKER}</script>`,
  `"><img src=x onerror=${XSS_MARKER}>`,
];

/**
 * Pure analyzer: detect the probe marker reflected into the response without
 * HTML encoding. Escaped markers (`&lt;anbumarker&gt;`) are treated as safe.
 */
export function analyzeXss(observation: XssObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const rawTag = `<${XSS_MARKER}`;
  const escapedTag = `&lt;${XSS_MARKER}`;

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0 || !body.includes(XSS_MARKER)) continue;

    const raw = body.includes(rawTag) || body.includes(`<script>${XSS_MARKER}</script>`);
    if (raw) {
      findings.push({
        title: "Unescaped HTML reflection of the XSS probe",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
        ],
        remediation:
          "Contextually encode all reflected output (HTML, attribute, JavaScript, URL) and deploy a restrictive Content-Security-Policy.",
        details: `Payload ${probe.payload} was reflected without HTML encoding.`,
        falsePositiveAnalysis:
          "The marker appears inside unescaped HTML markup, so the reflection reaches the browser as active markup.",
      });
      continue;
    }

    const escaped = body.includes(escapedTag) || body.includes(`&lt;script&gt;${XSS_MARKER}`);
    if (!escaped) {
      findings.push({
        title: "XSS probe reflected without obvious HTML encoding",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "medium",
        confidence: "unverified",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
        ],
        remediation:
          "Contextually encode all reflected output and verify the response content type before rendering.",
        details: `Payload ${probe.payload} was reflected but the encoding could not be confirmed.`,
        falsePositiveAnalysis:
          "The marker was reflected without a recognizable encoding escape; manual confirmation is required.",
      });
    }
  }

  return findings;
}

export const xssCheck: Check = {
  metadata: {
    id: "xss",
    toolName: "check_xss",
    title: "Cross-site scripting reflection probes",
    description:
      "Tests reflection in HTML, attribute, and script contexts with harmless markers and ignores encoded output.",
    category: "A05",
    categories: ["A05"],
    cwe: "CWE-79",
    relatedCwes: ["CWE-116", "CWE-80"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: XSS_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A05_2025-Injection/",
      "https://cwe.mitre.org/data/definitions/79.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(ctx, [], [], undefined, "xss check requires a parameter name");
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "xss check received no response");
    }

    const probes: XssProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of XSS_PAYLOADS) {
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
    const candidates = analyzeXss({
      url: input.url,
      parameter,
      baseline: primary.response,
      probes,
    });
    return checkResult(ctx, materialize(xssCheck.metadata, candidates, evidence), evidence);
  },
};
