import type { CandidateFinding, Check, CheckResponse, CheckResult, EvidenceRef } from "./types.js";
import { checkResult } from "./types.js";
import { captureResponse, fetchPrimary, materialize, parseJsonBody } from "./util.js";

const CONTEXT_HASH =
  /(?:password|passwd|pwd|hash|secret|credential)["'\s:=]{1,12}([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/i;
const MD5CRYPT = /\$1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22}/;
const MYSQL_HASH = /\*[0-9A-Fa-f]{40,41}\b/;
const STRONG_HASH = /^\$(?:2[aby]|argon2|pbkdf2|scrypt|6\$|5\$|y\$)/i;

function collectPlainPasswordPaths(value: unknown, path: string, out: string[]): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectPlainPasswordPaths(item, `${path}[${index}]`, out));
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = path === "" ? key : `${path}.${key}`;
    if (typeof child === "string" && /password|passwd|pwd/i.test(key)) {
      if (!STRONG_HASH.test(child) && child.length >= 4) out.push(childPath);
    } else {
      collectPlainPasswordPaths(child, childPath, out);
    }
  }
}

/**
 * Pure analyzer: detect exposed password hashes and cleartext password fields
 * in a response body. Strong hashes (bcrypt, argon2, PBKDF2, scrypt, sha512crypt)
 * are ignored.
 */
export function analyzePasswordHash(response: CheckResponse): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const body = response.bodyText;
  if (body.length === 0) return findings;

  const contextMatch = CONTEXT_HASH.exec(body);
  if (contextMatch !== null) {
    findings.push({
      title: "Weak password hash exposed in response",
      affected: { url: response.url },
      severity: "high",
      reproduction: [`Send ${response.method} ${response.url} and inspect the response body.`],
      remediation:
        "Do not expose password hashes; store passwords with a memory-hard KDF (argon2id, scrypt, or bcrypt) and never return them in API responses.",
      details: `Matched a password-related field next to a ${contextMatch[1].length}-character hex digest.`,
    });
  }

  const md5crypt = MD5CRYPT.exec(body);
  if (md5crypt !== null) {
    findings.push({
      title: "Legacy md5crypt password hash exposed",
      affected: { url: response.url },
      severity: "high",
      reproduction: [`Send ${response.method} ${response.url} and inspect the response body.`],
      remediation: "Migrate md5crypt hashes to argon2id, scrypt, or bcrypt on next authentication.",
      details: "Detected an `$1$` md5crypt hash.",
    });
  }

  const mysqlHash = MYSQL_HASH.exec(body);
  if (mysqlHash !== null) {
    findings.push({
      title: "Legacy MySQL password hash exposed",
      affected: { url: response.url },
      severity: "high",
      reproduction: [`Send ${response.method} ${response.url} and inspect the response body.`],
      remediation: "Use a modern memory-hard password KDF instead of MySQL's legacy hash.",
      details: "Detected a `*SHA1(...)` MySQL password hash.",
    });
  }

  const json = parseJsonBody(body);
  if (json !== undefined) {
    const paths: string[] = [];
    collectPlainPasswordPaths(json, "", paths);
    for (const path of paths) {
      findings.push({
        title: "Password value returned in response",
        affected: { url: response.url },
        severity: "high",
        reproduction: [`Send ${response.method} ${response.url} and inspect the JSON response.`],
        remediation:
          "Never return password values (even hashed) in API responses; store them only with a memory-hard KDF.",
        details: `JSON field ${path} contains a non-hash password value.`,
      });
    }
  }

  return findings;
}

export const passwordHashCheck: Check = {
  metadata: {
    id: "password-hash",
    toolName: "check_password_hash",
    title: "Exposed password hashes and cleartext password fields",
    description:
      "Inspects response bodies for weak password hash formats and cleartext password fields while ignoring strong KDF hashes.",
    category: "A04",
    categories: ["A04"],
    cwe: "CWE-916",
    relatedCwes: ["CWE-759", "CWE-522"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 1,
    references: [
      "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
      "https://cwe.mitre.org/data/definitions/916.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "password-hash check received no response");
    }
    const evidence: EvidenceRef[] = [];
    const captured = await captureResponse(ctx, primary.request, primary.response);
    if (captured !== undefined) evidence.push(captured);
    const candidates = analyzePasswordHash(primary.response);
    return checkResult(
      ctx,
      materialize(passwordHashCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
