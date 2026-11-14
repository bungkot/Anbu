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
  isSuccessStatus,
  materialize,
  readOptionStringArray,
} from "./util.js";

const ADMIN_MARKERS: readonly RegExp[] = [
  /\badmin(?:istration|istrator)?\b/i,
  /\bdashboard\b/i,
  /\buser(?: list| management|s)\b/i,
  /\bconfiguration\b/i,
  /\bserver status\b/i,
  /\bphpinfo\b/i,
  /\bindex of \//i,
  /\bactuator\b/i,
  /\bbackup\b/i,
];

const LOGIN_MARKERS: readonly RegExp[] = [
  /<title[^>]*>[^<]*(?:login|sign in|log in)/i,
  /name=["']password["']/i,
  /type=["']password["']/i,
];

/** Sensitive files that are worth reporting even without admin markers. */
const SENSITIVE_FILE_MARKERS: Readonly<Record<string, RegExp>> = {
  "/.env": /^\s*(?:APP_KEY|DB_PASSWORD|SECRET|API_KEY|PASSWORD)=/m,
  "/.git/config": /\[core\]/,
};

const DEFAULT_PATHS: readonly string[] = [
  "/admin",
  "/admin/",
  "/admin/users",
  "/administrator",
  "/api/admin",
  "/api/users",
  "/config",
  "/configuration",
  "/backup",
  "/backups",
  "/internal",
  "/debug",
  "/phpinfo.php",
  "/server-status",
  "/actuator",
  "/actuator/env",
  "/.git/config",
  "/.env",
];

export interface ForceBrowsingProbe {
  path: string;
  response: CheckResponse;
}

export interface ForceBrowsingObservation {
  url: string;
  probes: ForceBrowsingProbe[];
}

/**
 * Pure analyzer: report privileged paths that return admin content without
 * authentication. Login pages are ignored because they are expected to be
 * reachable.
 */
export function analyzeForceBrowsing(observation: ForceBrowsingObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    if (!isSuccessStatus(probe.response.status)) continue;
    if (LOGIN_MARKERS.some((pattern) => pattern.test(body))) continue;

    const sensitiveMarker = SENSITIVE_FILE_MARKERS[probe.path];
    if (sensitiveMarker !== undefined) {
      if (!sensitiveMarker.test(body)) continue;
      findings.push({
        title: `Sensitive file ${probe.path} is readable without authorization`,
        affected: { url: observation.url, endpoint: probe.path },
        severity: "high",
        reproduction: [
          `Send GET ${observation.url}${probe.path} without a session and inspect the response.`,
        ],
        remediation:
          "Never expose configuration or source-control files through the web root; serve them only from outside the document root and block the paths in the web server.",
        details: `The path returned HTTP ${probe.response.status} with sensitive file content.`,
        falsePositiveAnalysis:
          "The response contains the expected structure of a protected configuration file, so the file is readable anonymously.",
      });
      continue;
    }

    if (!ADMIN_MARKERS.some((pattern) => pattern.test(body))) continue;
    findings.push({
      title: `Privileged path ${probe.path} is reachable without authorization`,
      affected: { url: observation.url, endpoint: probe.path },
      severity: "high",
      reproduction: [
        `Send GET ${observation.url}${probe.path} without a session and inspect the response.`,
      ],
      remediation:
        "Require authentication and role-based authorization for every privileged path; do not rely on the URL being unguessable.",
      details: `The path returned HTTP ${probe.response.status} with administrative content.`,
      falsePositiveAnalysis:
        "The response is successful and contains administrative markers but no login form, so the content is exposed without authentication.",
    });
  }

  return findings;
}

export const forceBrowsingCheck: Check = {
  metadata: {
    id: "force-browsing",
    toolName: "check_force_browsing",
    title: "Force browsing of privileged paths",
    description:
      "Requests privileged URLs unauthenticated and detects administrative content in the response.",
    category: "A01",
    categories: ["A01"],
    cwe: "CWE-284",
    relatedCwes: ["CWE-306", "CWE-862"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: DEFAULT_PATHS.length + 1,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/284.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const paths =
      readOptionStringArray(input.options, "paths") ??
      (readOptionStringArray(input.options, "endpoints") || DEFAULT_PATHS);

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "force-browsing check received no response");
    }

    const base = input.url.replace(/\/+$/, "");
    const probes: ForceBrowsingProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const path of paths) {
      const normalized = path.startsWith("/") ? path : `/${path}`;
      const result = await ctx.fetch({ method: "GET", url: `${base}${normalized}` });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ path: normalized, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeForceBrowsing({ url: base, probes });
    return checkResult(
      ctx,
      materialize(forceBrowsingCheck.metadata, candidates, evidence),
      evidence,
    );
  },
};
