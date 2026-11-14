import type {
  CandidateFinding,
  Check,
  CheckResponse,
  CheckResult,
} from "./types.js";
import { checkResult } from "./types.js";
import { captureAll, fetchPrimary, headerValue, materialize } from "./util.js";

/** Origins used to test the CORS policy. */
const TEST_ORIGINS: readonly string[] = ["https://evil.test", "null"];

export interface CorsProbe {
  origin: string;
  response: CheckResponse;
}

export interface CorsObservation {
  url: string;
  probes: CorsProbe[];
}

/**
 * Pure analyzer: report when the server reflects an unauthorized origin and
 * allows credentials, or reflects an arbitrary origin without credentials.
 */
export function analyzeCors(observation: CorsObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const probe of observation.probes) {
    const headers = probe.response.headers;
    const allowOrigin = headerValue(headers, "access-control-allow-origin");
    if (allowOrigin === undefined) continue;
    const allowCredentials =
      headerValue(headers, "access-control-allow-credentials")?.toLowerCase() === "true";
    const allowed = allowOrigin.trim().toLowerCase();
    const origin = probe.origin.trim().toLowerCase();

    if (allowed === "*") {
      if (allowCredentials) {
        findings.push({
          title: "CORS allows any origin together with credentials",
          affected: { url: observation.url },
          severity: "high",
          reproduction: [
            `Send GET ${observation.url} with Origin: ${probe.origin} and inspect the CORS response headers.`,
          ],
          remediation:
            "Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`; use an explicit origin allowlist.",
          details: "The server returned `Access-Control-Allow-Origin: *` with credentials enabled.",
          falsePositiveAnalysis:
            "The wildcard origin with credentials is rejected by browsers but signals a permissive CORS policy; an explicit allowlist is required.",
        });
      }
      continue;
    }

    if (allowed !== origin && allowed !== "null") continue;
    findings.push({
      title: allowCredentials
        ? "CORS reflects an unauthorized origin with credentials"
        : "CORS reflects an unauthorized origin",
      affected: { url: observation.url },
      severity: allowCredentials ? "high" : "medium",
      reproduction: [
        `Send GET ${observation.url} with Origin: ${probe.origin} and inspect the CORS response headers.`,
      ],
      remediation:
        "Use an explicit origin allowlist, validate the Origin header on every request, and only enable credentials for trusted origins.",
      details: `Access-Control-Allow-Origin: ${allowOrigin} (credentials: ${allowCredentials}).`,
      falsePositiveAnalysis:
        "The server echoed the probe origin that is not part of any trusted allowlist, so cross-origin attackers can read the response.",
    });
  }

  return findings;
}

export const corsCheck: Check = {
  metadata: {
    id: "cors",
    toolName: "check_cors",
    title: "CORS policy probes",
    description:
      "Tests CORS with unauthorized origins and detects credentialed or arbitrary-origin responses.",
    category: "A01",
    categories: ["A01"],
    cwe: "CWE-942",
    relatedCwes: ["CWE-346", "CWE-639"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: TEST_ORIGINS.length + 1,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/942.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Prevention_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "cors check received no response");
    }

    const probes: CorsProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const origin of TEST_ORIGINS) {
      const result = await ctx.fetch({
        method: "GET",
        url: input.url,
        headers: { ...(input.headers ?? {}), origin },
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ origin, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeCors({ url: input.url, probes });
    return checkResult(ctx, materialize(corsCheck.metadata, candidates, evidence), evidence);
  },
};
