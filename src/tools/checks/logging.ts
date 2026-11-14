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
  isSuccessStatus,
  materialize,
  readOptionStringArray,
} from "./util.js";

const DEFAULT_LOG_PATHS: readonly string[] = [
  "/audit",
  "/audit/log",
  "/api/audit",
  "/logs",
  "/api/logs",
  "/admin/audit-log",
];

const EVENT_MARKERS: readonly RegExp[] = [
  /"event"\s*:\s*"(?:login|logout|failed[-_ ]?login|access)"/i,
  /"action"\s*:\s*"(?:login|logout|failed[-_ ]?login)"/i,
  /\blogin (?:success|failed)\b/i,
  /\bfailed login\b/i,
  /user=admin/i,
];

const CORRELATION_HEADERS: readonly string[] = [
  "x-request-id",
  "x-correlation-id",
  "x-trace-id",
];

export interface LoggingProbe {
  path: string;
  response: CheckResponse;
}

export interface LoggingObservation {
  url: string;
  primary: CheckResponse;
  probes: LoggingProbe[];
}

/**
 * Pure analyzer: report audit-log endpoints that expose security events
 * without authorization, and report the absence of any correlation/logging
 * evidence on the primary response.
 */
export function analyzeLogging(observation: LoggingObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    if (!isSuccessStatus(probe.response.status)) continue;
    if (!EVENT_MARKERS.some((pattern) => pattern.test(body))) continue;
    findings.push({
      title: `Audit log endpoint ${probe.path} exposes security events without authorization`,
      affected: { url: observation.url, endpoint: probe.path },
      severity: "high",
      reproduction: [
        `Send GET ${observation.url}${probe.path} without a session and inspect the response.`,
      ],
      remediation:
        "Restrict audit-log access to authorized administrators, and never expose other users' authentication events anonymously.",
      details: `The endpoint returned HTTP ${probe.response.status} with authentication events.`,
      falsePositiveAnalysis:
        "The response contains login/logout events for accounts other than the caller and required no authentication.",
    });
  }

  const hasCorrelation = CORRELATION_HEADERS.some(
    (name) => headerValue(observation.primary.headers, name) !== undefined,
  );
  if (!hasCorrelation && findings.length === 0) {
    findings.push({
      title: "No evidence of security event logging or request correlation",
      affected: { url: observation.url },
      severity: "low",
      confidence: "unverified",
      reproduction: [
        `Inspect the response headers and body for ${observation.url} and look for a correlation id or audit log reference.`,
      ],
      remediation:
        "Log authentication, authorization, and security-relevant events with a correlation id, and forward them to a tamper-evident store.",
      details:
        "The response carried no correlation header and no reachable audit-log endpoint exposed security events.",
      falsePositiveAnalysis:
        "The absence of logging evidence is not proof that logging is disabled; it is a low-confidence design signal that requires manual confirmation.",
    });
  }

  return findings;
}

export const loggingCheck: Check = {
  metadata: {
    id: "logging",
    toolName: "check_logging",
    title: "Security event logging and audit exposure",
    description:
      "Verifies that test login/access events are logged and alertable, and detects anonymously exposed audit logs.",
    category: "A09",
    categories: ["A09"],
    cwe: "CWE-778",
    relatedCwes: ["CWE-532", "CWE-220"],
    readOnly: true,
    requiresApproval: false,
    severity: "medium",
    maxRequests: DEFAULT_LOG_PATHS.length + 1,
    references: [
      "https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/",
      "https://cwe.mitre.org/data/definitions/778.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const paths =
      readOptionStringArray(input.options, "paths") ??
      (readOptionStringArray(input.options, "endpoints") || DEFAULT_LOG_PATHS);

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "logging check received no response");
    }

    const base = input.url.replace(/\/+$/, "");
    const probes: LoggingProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const path of paths) {
      const normalized = path.startsWith("/") ? path : `/${path}`;
      const result = await ctx.fetch({ method: "GET", url: `${base}${normalized}` });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ path: normalized, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeLogging({ url: base, primary: primary.response, probes });
    return checkResult(ctx, materialize(loggingCheck.metadata, candidates, evidence), evidence);
  },
};
