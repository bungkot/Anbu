import type { CandidateFinding, Check, CheckResult, EvidenceRef } from "./types.js";
import { checkResult } from "./types.js";
import {
  captureResponse,
  cookiesFromHeaders,
  fetchPrimary,
  headerValue,
  materialize,
} from "./util.js";

export interface SecurityHeadersObservation {
  url: string;
  headers: Record<string, string>;
}

function hasAttribute(cookie: { attributes: Record<string, string> }, name: string): boolean {
  return cookie.attributes[name] !== undefined;
}

/**
 * Pure analyzer: inspect security response headers and cookie flags. It makes
 * no network calls and returns only high-signal, defence-in-depth findings.
 */
export function analyzeSecurityHeaders(
  observation: SecurityHeadersObservation,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const { url, headers } = observation;

  let isHttps: boolean;
  try {
    isHttps = new URL(url).protocol === "https:";
  } catch {
    return findings;
  }

  const hsts = headerValue(headers, "strict-transport-security");
  if (isHttps && hsts === undefined) {
    findings.push({
      title: "Strict-Transport-Security header is missing",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation:
        "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.",
      details: "HSTS was absent from the HTTPS response.",
    });
  } else if (isHttps && hsts !== undefined) {
    const maxAge = /max-age=(\d+)/i.exec(hsts);
    if (maxAge === null) {
      findings.push({
        title: "Strict-Transport-Security header has no max-age",
        affected: { url },
        severity: "low",
        reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
        remediation: "Add a long `max-age` (at least 31536000 seconds) to the HSTS header.",
        details: `HSTS value: ${hsts}`,
      });
    } else if (Number(maxAge[1]) < 31_536_000) {
      findings.push({
        title: "Strict-Transport-Security max-age is too short",
        affected: { url },
        severity: "low",
        reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
        remediation: "Use a max-age of at least 31536000 seconds (one year).",
        details: `HSTS max-age: ${maxAge[1]}`,
      });
    }
  }

  const csp = headerValue(headers, "content-security-policy");
  const frameAncestors = csp !== undefined && /frame-ancestors/i.test(csp);
  if (csp === undefined) {
    findings.push({
      title: "Content-Security-Policy header is missing",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation:
        "Deploy a restrictive Content-Security-Policy appropriate to the application; avoid `unsafe-inline` and `unsafe-eval`.",
      details: "CSP was absent from the response.",
    });
  } else if (/unsafe-inline|unsafe-eval/i.test(csp) && !/nonce-|sha(?:256|384|512)-/i.test(csp)) {
    findings.push({
      title: "Content-Security-Policy allows unsafe script execution",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation:
        "Remove `unsafe-inline` and `unsafe-eval`; use nonces or hashes for required inline scripts.",
      details: `CSP value: ${csp}`,
    });
  }

  const xFrameOptions = headerValue(headers, "x-frame-options");
  if (xFrameOptions === undefined && !frameAncestors) {
    findings.push({
      title: "X-Frame-Options header is missing and CSP has no frame-ancestors",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation:
        "Set `X-Frame-Options: DENY` (or SAMEORIGIN) or add a CSP `frame-ancestors` directive.",
      details: "Neither X-Frame-Options nor CSP frame-ancestors was present.",
    });
  } else if (xFrameOptions !== undefined && !/deny|sameorigin/i.test(xFrameOptions)) {
    findings.push({
      title: "X-Frame-Options header has an unsafe value",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Use `X-Frame-Options: DENY` or `SAMEORIGIN`.",
      details: `X-Frame-Options value: ${xFrameOptions}`,
    });
  }

  const referrerPolicy = headerValue(headers, "referrer-policy");
  if (referrerPolicy === undefined) {
    findings.push({
      title: "Referrer-Policy header is missing",
      affected: { url },
      severity: "low",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
      details: "Referrer-Policy was absent from the response.",
    });
  } else if (/unsafe-url/i.test(referrerPolicy)) {
    findings.push({
      title: "Referrer-Policy allows unsafe URL leakage",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Remove `unsafe-url`; use `strict-origin-when-cross-origin` or stricter.",
      details: `Referrer-Policy value: ${referrerPolicy}`,
    });
  }

  if (headerValue(headers, "permissions-policy") === undefined) {
    findings.push({
      title: "Permissions-Policy header is missing",
      affected: { url },
      severity: "low",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Set a Permissions-Policy that disables features the application does not use.",
      details: "Permissions-Policy was absent from the response.",
    });
  }

  const contentTypeOptions = headerValue(headers, "x-content-type-options");
  if (contentTypeOptions === undefined || !/nosniff/i.test(contentTypeOptions)) {
    findings.push({
      title: "X-Content-Type-Options header is missing or invalid",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Set `X-Content-Type-Options: nosniff` on all responses.",
      details:
        contentTypeOptions === undefined
          ? "X-Content-Type-Options was absent."
          : `X-Content-Type-Options value: ${contentTypeOptions}`,
    });
  }

  for (const cookie of cookiesFromHeaders(headers)) {
    if (isHttps && !hasAttribute(cookie, "secure")) {
      findings.push({
        title: `Cookie "${cookie.name}" is missing the Secure attribute`,
        affected: { url },
        severity: "medium",
        reproduction: [`Send a GET request to ${url} and inspect the Set-Cookie headers.`],
        remediation: "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
        details: `Set-Cookie: ${cookie.name}=...`,
      });
    }
    if (!hasAttribute(cookie, "httponly")) {
      findings.push({
        title: `Cookie "${cookie.name}" is missing the HttpOnly attribute`,
        affected: { url },
        severity: "medium",
        reproduction: [`Send a GET request to ${url} and inspect the Set-Cookie headers.`],
        remediation: "Add the `HttpOnly` attribute to prevent script access to the cookie.",
        details: `Set-Cookie: ${cookie.name}=...`,
      });
    }
    if (!hasAttribute(cookie, "samesite")) {
      findings.push({
        title: `Cookie "${cookie.name}" is missing the SameSite attribute`,
        affected: { url },
        severity: "medium",
        reproduction: [`Send a GET request to ${url} and inspect the Set-Cookie headers.`],
        remediation: "Set `SameSite=Lax` or `SameSite=Strict` on the cookie.",
        details: `Set-Cookie: ${cookie.name}=...`,
      });
    }
  }

  return findings;
}

export const securityHeadersCheck: Check = {
  metadata: {
    id: "security-headers",
    toolName: "check_security_headers",
    title: "Security response headers and cookie flags",
    description:
      "Inspects HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options, and cookie flags.",
    category: "A02",
    categories: ["A02"],
    cwe: "CWE-693",
    relatedCwes: ["CWE-1004", "CWE-614"],
    readOnly: true,
    requiresApproval: false,
    severity: "medium",
    maxRequests: 1,
    references: [
      "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "security-headers check received no response");
    }
    const evidence: EvidenceRef[] = [];
    const captured = await captureResponse(ctx, primary.request, primary.response);
    if (captured !== undefined) evidence.push(captured);

    const candidates = analyzeSecurityHeaders({
      url: primary.response.url,
      headers: primary.response.headers,
    });
    return checkResult(
      ctx,
      materialize(securityHeadersCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
