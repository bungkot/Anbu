import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import {
  captureAll,
  fetchPrimary,
  isSuccessStatus,
  materialize,
  readOptionString,
  withQuery,
} from "./util.js";

export interface SqlProbe {
  payload: string;
  response: CheckResponse;
}

export interface SqlInjectionObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: SqlProbe[];
}

/** Database error signatures that are not expected in a normal response. */
const SQL_ERROR_SIGNATURES: readonly RegExp[] = [
  /you have an error in your sql syntax/i,
  /unclosed quotation mark/i,
  /sqlsyntaxerror/i,
  /mysql_fetch_/i,
  /pg_query\s*\(/i,
  /sqlite3?::/i,
  /ora-\d{5}/i,
  /microsoft ole db provider/i,
  /jdbc[^]{0,80}sql/i,
  /syntax error at or near/i,
  /unterminated quoted string/i,
  /warning:\s*mysql/i,
  /quoted string not properly terminated/i,
  /sqlstate\[\d+\]/i,
  /driver[^]{0,80}sql/i,
  /psql.*?fatal:/i,
  /db2 sql error/i,
];

const SQLI_PAYLOADS: readonly string[] = [
  "'",
  '"',
  "1 AND 1=1",
  "1 AND 1=2",
  "1;--",
  "1' ORDER BY 1-- -",
  "' OR '1'='1",
];

/**
 * Pure analyzer: detect database error signatures and boolean-based
 * differentials caused by the SQLi probes. A signature that is already present
 * in the baseline is ignored, so a noisy application does not trigger a finding.
 */
export function analyzeSqlInjection(observation: SqlInjectionObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineBody = observation.baseline.bodyText;
  const seenSignatures = new Set<string>();

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    for (const pattern of SQL_ERROR_SIGNATURES) {
      const match = pattern.exec(body);
      if (match === null) continue;
      if (pattern.test(baselineBody)) continue;
      const key = `${probe.payload}\u0000${pattern.source}`;
      if (seenSignatures.has(key)) continue;
      seenSignatures.add(key);
      findings.push({
        title: "SQL error message reflected after an injection probe",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
        ],
        remediation:
          "Use parameterized queries or a query builder for every database call; never concatenate user input into SQL.",
        details: `Payload ${probe.payload} produced the database error "${match[0]}".`,
        falsePositiveAnalysis:
          "The error signature appears only after the probe and is absent from the baseline response.",
      });
      break;
    }
  }

  const trueProbe = observation.probes.find((probe) => /(^|[^0-9])1\s*=\s*1/.test(probe.payload));
  const falseProbe = observation.probes.find((probe) => /(^|[^0-9])1\s*=\s*2/.test(probe.payload));
  if (trueProbe !== undefined && falseProbe !== undefined) {
    const trueBody = trueProbe.response.bodyText.trim();
    const falseBody = falseProbe.response.bodyText.trim();
    const reflected =
      trueBody.includes(trueProbe.payload) || falseBody.includes(falseProbe.payload);
    const different = trueBody !== falseBody;
    if (
      !reflected &&
      different &&
      trueBody.length > 0 &&
      falseBody.length > 0 &&
      isSuccessStatus(trueProbe.response.status) &&
      isSuccessStatus(falseProbe.response.status)
    ) {
      findings.push({
        title: "Boolean-based SQL injection differential observed",
        affected: { url: observation.url, parameter: observation.parameter },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url} with ${observation.parameter}=1 AND 1=1 and again with 1 AND 1=2; compare the responses.`,
        ],
        remediation:
          "Use parameterized queries and ensure the application does not branch on SQL boolean expressions derived from input.",
        details: "The true and false SQL conditions produced different successful responses.",
        falsePositiveAnalysis:
          "The payloads were not reflected verbatim and both requests succeeded, so the difference is server-side behavior.",
      });
    }
  }

  return findings;
}

export const sqliCheck: Check = {
  metadata: {
    id: "sqli",
    toolName: "check_sqli",
    title: "SQL injection probes",
    description:
      "Sends parameterized, non-destructive SQL probes and analyzes error messages and boolean differentials.",
    category: "A05",
    categories: ["A05"],
    cwe: "CWE-89",
    relatedCwes: ["CWE-94", "CWE-116"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: SQLI_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A05_2025-Injection/",
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(ctx, [], [], undefined, "sqli check requires a parameter name");
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "sqli check received no response");
    }

    const probes: SqlProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of SQLI_PAYLOADS) {
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
    const candidates = analyzeSqlInjection({
      url: input.url,
      parameter,
      baseline: primary.response,
      probes,
    });
    return checkResult(ctx, materialize(sqliCheck.metadata, candidates, evidence, input), evidence);
  },
};
