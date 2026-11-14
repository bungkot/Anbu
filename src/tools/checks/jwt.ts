import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import { captureAll, fetchPrimary, headerValue, materialize, readOptionString } from "./util.js";

const JWT_PATTERN = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
const TOKEN_QUERY_KEYS = ["token", "access_token", "id_token", "jwt"];

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export interface JwtObservation {
  url: string;
  token: string;
  now?: Date;
}

/** Decode the header and payload of a JWT without verifying its signature. */
export function decodeJwt(token: string): DecodedJwt | undefined {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return undefined;
  const header = decodePart(parts[0]);
  const payload = decodePart(parts[1]);
  if (header === undefined || payload === undefined) return undefined;
  return { header, payload };
}

function decodePart(part: string): Record<string, unknown> | undefined {
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const parsed = JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** Extract a JWT from a response body or headers. */
export function extractJwt(response: CheckResponse): string | undefined {
  const bodyMatch = JWT_PATTERN.exec(response.bodyText);
  if (bodyMatch !== null) return bodyMatch[0];
  const setCookie = headerValue(response.headers, "set-cookie");
  if (setCookie !== undefined) {
    const cookieMatch = JWT_PATTERN.exec(setCookie);
    if (cookieMatch !== null) return cookieMatch[0];
  }
  const authorization = headerValue(response.headers, "authorization");
  if (authorization !== undefined) {
    const bearer = /\bBearer\s+(.+)$/i.exec(authorization);
    const candidate = bearer?.[1] ?? authorization;
    const authMatch = JWT_PATTERN.exec(candidate);
    if (authMatch !== null) return authMatch[0];
  }
  return undefined;
}

/**
 * Pure analyzer: detect unsigned tokens, the `none` algorithm, expired tokens,
 * and tokens exposed in the URL query string.
 */
export function analyzeJwt(observation: JwtObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const token = observation.token.trim();
  const now = observation.now ?? new Date();

  if (token.split(".").length !== 3) {
    findings.push({
      title: "JWT is missing its signature segment",
      affected: { url: observation.url },
      severity: "high",
      reproduction: [`Inspect the JWT returned by ${observation.url}.`],
      remediation:
        "Reject tokens that do not contain a header, payload, and signature; verify the signature with a strong algorithm.",
      details: "The token has fewer than three dot-separated segments.",
      falsePositiveAnalysis:
        "A signed JWT always has three segments; a two-segment token cannot carry a verifiable signature.",
    });
    return findings;
  }

  const decoded = decodeJwt(token);
  if (decoded === undefined) {
    findings.push({
      title: "JWT header or payload is not valid base64url JSON",
      affected: { url: observation.url },
      severity: "medium",
      confidence: "unverified",
      reproduction: [`Inspect the JWT returned by ${observation.url}.`],
      remediation:
        "Reject malformed tokens and validate the header and payload structure before use.",
      details: "The token segments could not be decoded as JSON.",
    });
    return findings;
  }

  const algorithm = decoded.header.alg;
  if (typeof algorithm === "string" && algorithm.toLowerCase() === "none") {
    findings.push({
      title: "JWT uses the 'none' algorithm",
      affected: { url: observation.url },
      severity: "high",
      reproduction: [`Inspect the JWT returned by ${observation.url}.`],
      remediation:
        "Reject tokens whose algorithm is `none`; require an asymmetric or HMAC algorithm and verify the signature.",
      details: "The JWT header declares `alg: none`.",
      falsePositiveAnalysis:
        "The token explicitly declares no signature algorithm, so any attacker can forge a token with an arbitrary payload.",
    });
  }

  const expiresAt = decoded.payload.exp;
  if (typeof expiresAt === "number" && Number.isFinite(expiresAt)) {
    if (expiresAt * 1000 < now.getTime()) {
      findings.push({
        title: "JWT is expired but still accepted by the application",
        affected: { url: observation.url },
        severity: "medium",
        reproduction: [`Inspect the JWT returned by ${observation.url}.`],
        remediation: "Validate the `exp` claim on every token and reject expired tokens.",
        details: `The token expired at ${new Date(expiresAt * 1000).toISOString()}.`,
      });
    }
  }

  const notBefore = decoded.payload.nbf;
  if (typeof notBefore === "number" && Number.isFinite(notBefore)) {
    if (notBefore * 1000 > now.getTime()) {
      findings.push({
        title: "JWT is used before its 'nbf' validity time",
        affected: { url: observation.url },
        severity: "medium",
        reproduction: [`Inspect the JWT returned by ${observation.url}.`],
        remediation: "Validate the `nbf` claim and reject tokens that are not yet valid.",
        details: `The token is valid from ${new Date(notBefore * 1000).toISOString()}.`,
      });
    }
  }

  try {
    const parsed = new URL(observation.url);
    for (const key of TOKEN_QUERY_KEYS) {
      if (parsed.searchParams.has(key)) {
        findings.push({
          title: "JWT is exposed in a URL query parameter",
          affected: { url: observation.url },
          severity: "medium",
          reproduction: [`Inspect the URL returned by ${observation.url}.`],
          remediation:
            "Never place tokens in URLs; use `Authorization` headers or `HttpOnly` cookies so they are not logged or leaked.",
          details: `The URL contains the query parameter \`${key}\`.`,
        });
        break;
      }
    }
  } catch {
    // A relative or invalid URL is not itself a finding.
  }

  return findings;
}

export const jwtCheck: Check = {
  metadata: {
    id: "jwt",
    toolName: "check_jwt",
    title: "JWT algorithm and claim checks",
    description:
      "Tests algorithm confusion, the 'none' algorithm, signature presence, expiry, and audience claims.",
    category: "A01",
    categories: ["A01", "A07"],
    cwe: "CWE-347",
    relatedCwes: ["CWE-345", "CWE-287"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 1,
    references: [
      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/347.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const supplied = readOptionString(input.options, "token");
    if (supplied !== undefined) {
      const candidates = analyzeJwt({ url: input.url, token: supplied, now: ctx.now() });
      return checkResult(ctx, materialize(jwtCheck.metadata, candidates, [], input), []);
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "jwt check received no response");
    }

    const token = extractJwt(primary.response);
    if (token === undefined) {
      return checkResult(ctx, [], [], undefined, "no JWT found in the response body or headers");
    }

    const evidence = await captureAll(ctx, [
      { request: primary.request, response: primary.response },
    ]);
    const candidates = analyzeJwt({ url: input.url, token, now: ctx.now() });
    return checkResult(ctx, materialize(jwtCheck.metadata, candidates, evidence, input), evidence);
  },
};
