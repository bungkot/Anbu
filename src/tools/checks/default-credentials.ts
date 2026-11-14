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
  readOptionString,
} from "./util.js";

export interface CredentialPair {
  username: string;
  password: string;
}

export interface DefaultCredentialProbe {
  username: string;
  response: CheckResponse;
}

export interface DefaultCredentialObservation {
  url: string;
  probes: DefaultCredentialProbe[];
}

const SUCCESS_MARKERS: readonly RegExp[] = [
  /\bwelcome\b/i,
  /\bdashboard\b/i,
  /\blogout\b/i,
  /\bsign out\b/i,
  /"success"\s*:\s*true/i,
];

function parseCredentials(value: unknown): CredentialPair[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const pairs: CredentialPair[] = [];
  for (const item of value) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    const username = record.username;
    const password = record.password;
    if (typeof username !== "string" || typeof password !== "string") continue;
    if (username.length === 0 || password.length === 0) continue;
    pairs.push({ username, password });
  }
  return pairs.length > 0 ? pairs : undefined;
}

/**
 * Pure analyzer: report documented default credentials that the application
 * accepts. A response is only treated as a successful login when it is a 2xx
 * and shows a session cookie, redirect, or a success marker.
 */
export function analyzeDefaultCredentials(
  observation: DefaultCredentialObservation,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const probe of observation.probes) {
    const response = probe.response;
    if (!isSuccessStatus(response.status)) continue;
    const setCookie = response.headers["set-cookie"];
    const location = response.headers["location"];
    const bodyMarker = SUCCESS_MARKERS.some((pattern) => pattern.test(response.bodyText));
    if (setCookie === undefined && location === undefined && !bodyMarker) continue;
    findings.push({
      title: `Default credentials are accepted for "${probe.username}"`,
      affected: { url: observation.url, parameter: probe.username },
      severity: "high",
      reproduction: [
        `Send a login request to ${observation.url} with username "${probe.username}" and the documented default password; inspect the response.`,
      ],
      remediation:
        "Change or disable default accounts, enforce a password policy, and require MFA for administrative accounts.",
      details: `The login succeeded with HTTP ${response.status} for the default account.`,
      falsePositiveAnalysis:
        "The response contains a session cookie, redirect, or success marker, so the default credential authenticated successfully.",
    });
  }

  return findings;
}

export const defaultCredentialsCheck: Check = {
  metadata: {
    id: "default-credentials",
    toolName: "check_default_credentials",
    title: "Documented default credentials",
    description:
      "Tests documented default credentials on test accounts only and reports successful authentication.",
    category: "A02",
    categories: ["A02", "A07"],
    cwe: "CWE-798",
    relatedCwes: ["CWE-1392", "CWE-287"],
    readOnly: false,
    requiresApproval: true,
    severity: "high",
    maxRequests: 6,
    references: [
      "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/",
      "https://cwe.mitre.org/data/definitions/798.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const credentials = parseCredentials(input.options?.credentials);
    if (credentials === undefined) {
      return checkResult(
        ctx,
        [],
        [],
        undefined,
        "default-credentials check requires options.credentials with username/password pairs",
      );
    }

    const usernameField = readOptionString(input.options, "usernameField") ?? "username";
    const passwordField = readOptionString(input.options, "passwordField") ?? "password";

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "default-credentials check received no response");
    }

    const headers: Record<string, string> = {
      ...(input.headers ?? {}),
      "content-type": "application/json",
    };
    const limited = credentials.slice(0, defaultCredentialsCheck.metadata.maxRequests - 1);
    const probes: DefaultCredentialProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const credential of limited) {
      const body = JSON.stringify({
        [usernameField]: credential.username,
        [passwordField]: credential.password,
      });
      const result = await ctx.fetch({
        method: "POST",
        url: input.url,
        headers,
        body,
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ username: credential.username, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeDefaultCredentials({ url: input.url, probes });
    return checkResult(
      ctx,
      materialize(defaultCredentialsCheck.metadata, candidates, evidence),
      evidence,
    );
  },
};
