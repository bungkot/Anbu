import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { normalizeUrl, parseHtmlPage } from "../tools/crawl.js";
import type { CrawledAsset, CrawledForm, TechnologyMarker } from "../tools/crawl.js";

export const EVIDENCE_ID_PREFIX = "sha256:";
export const DEFAULT_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
export const REDACTED = "[REDACTED]";

const HASH_PATTERN = /^[a-f0-9]{64}$/i;

/**
 * Headers whose value is always a credential. Cookie headers are handled
 * separately so cookie names survive for structured parsing.
 */
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
  "x-csrf-token",
  "x-xsrf-token",
]);

const SENSITIVE_QUERY_KEYS = new Set([
  "access_token",
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "id_token",
  "passwd",
  "password",
  "pwd",
  "refresh_token",
  "secret",
  "session",
  "sessionid",
  "sid",
  "token",
]);

const SENSITIVE_BODY_KEYS = new Set([...SENSITIVE_QUERY_KEYS, "card_number", "cvv", "ssn"]);

const COOKIE_ATTRIBUTES = new Set([
  "domain",
  "expires",
  "httponly",
  "max-age",
  "partitioned",
  "path",
  "samesite",
  "secure",
]);

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g;
const BEARER_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi;
// The prefix group includes `^` so a credential at the very start of the body
// (for example `access_token=secret`) is still redacted.
const ASSIGNMENT_PATTERN =
  /(^|[?&=;\s"'])(access_token|api_key|apikey|auth|authorization|id_token|passwd|password|pwd|refresh_token|secret|session|sessionid|sid|token)([=:])([^&;\s"']+)/gi;

export interface EvidenceRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface EvidenceResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body?: string;
  bodyBytes: number;
  truncated: boolean;
  durationMs: number;
}

export interface EvidenceArtifact {
  version: 1;
  id: string;
  sha256: string;
  createdAt: string;
  sizeBytes: number;
  request: EvidenceRequest;
  response: EvidenceResponse;
}

export interface CaptureInput {
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: string;
    bodyBytes?: number;
    truncated?: boolean;
    durationMs?: number;
  };
}

export interface EvidenceStoreOptions {
  rootDir: string;
  /** Maximum serialized artifact size. Larger artifacts are refused. */
  maxArtifactBytes?: number;
  now?: () => Date;
}

export type CaptureResult =
  | { ok: true; evidenceId: string; sha256: string; path: string; sizeBytes: number }
  | { ok: false; error: string };

export interface EvidenceHeaderDiff {
  name: string;
  candidate?: string;
  baseline?: string;
}

export interface EvidenceComparison {
  candidateId: string;
  baselineId: string;
  status: { candidate: number; baseline: number; changed: boolean };
  headers: EvidenceHeaderDiff[];
  body: {
    changed: boolean;
    candidateBytes: number;
    baselineBytes: number;
    candidateSha256: string;
    baselineSha256: string;
  };
}

export type CompareResult =
  { ok: true; comparison: EvidenceComparison } | { ok: false; error: string };

export interface ParsedResponseFacts {
  evidenceId: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  cookies: string[];
  forms: CrawledForm[];
  assets: CrawledAsset[];
  links: string[];
  technologies: TechnologyMarker[];
}

export type ParseResult = { ok: true; facts: ParsedResponseFacts } | { ok: false; error: string };

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function redactCookieHeader(value: string, isResponse: boolean): string {
  return value
    .split(";")
    .map((part, index) => {
      const trimmed = part.trim();
      const equals = trimmed.indexOf("=");
      if (equals <= 0) return trimmed;
      const name = trimmed.slice(0, equals);
      if (isResponse && index > 0 && COOKIE_ATTRIBUTES.has(name.toLowerCase())) {
        return trimmed;
      }
      return `${name}=${REDACTED}`;
    })
    .join("; ");
}

function redactHeaders(
  headers: Record<string, string> | undefined,
  isResponse: boolean,
): Record<string, string> {
  const redacted: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    const lower = name.toLowerCase();
    if (lower === "cookie" || lower === "set-cookie") {
      redacted[name] = redactCookieHeader(value, isResponse);
    } else if (SENSITIVE_HEADERS.has(lower)) {
      redacted[name] = REDACTED;
    } else {
      redacted[name] = value;
    }
  }
  return redacted;
}

function redactUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return raw;
  }
  if (url.username !== "" || url.password !== "") {
    url.username = REDACTED;
    url.password = REDACTED;
  }
  for (const key of [...url.searchParams.keys()]) {
    if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
      url.searchParams.set(key, REDACTED);
    }
  }
  return url.toString();
}

function redactWithValueRegex(text: string): string {
  return text
    .replace(JWT_PATTERN, REDACTED)
    .replace(BEARER_PATTERN, `$1${REDACTED}`)
    .replace(ASSIGNMENT_PATTERN, (_match, prefix: string, key: string, separator: string) => {
      void separator;
      return `${prefix}${key}=${REDACTED}`;
    });
}

function redactJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactJsonValue);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_BODY_KEYS.has(key.toLowerCase()) ? REDACTED : redactJsonValue(child);
    }
    return out;
  }
  if (typeof value === "string") return redactWithValueRegex(value);
  return value;
}

function redactFormBody(body: string): string {
  const params = new URLSearchParams(body);
  for (const key of [...params.keys()]) {
    if (SENSITIVE_BODY_KEYS.has(key.toLowerCase())) params.set(key, REDACTED);
  }
  return params.toString();
}

function redactBody(body: string | undefined, contentType: string): string | undefined {
  if (body === undefined) return undefined;
  const type = contentType.toLowerCase();
  if (type.includes("application/json")) {
    try {
      return JSON.stringify(redactJsonValue(JSON.parse(body)));
    } catch {
      return redactWithValueRegex(body);
    }
  }
  if (type.includes("application/x-www-form-urlencoded")) {
    return redactFormBody(body);
  }
  return redactWithValueRegex(body);
}

function parseCookieNames(headers: Record<string, string>): string[] {
  const names = new Set<string>();
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== "set-cookie") continue;
    for (const part of value.split(";")) {
      const trimmed = part.trim();
      const equals = trimmed.indexOf("=");
      if (equals <= 0) continue;
      const cookieName = trimmed.slice(0, equals);
      if (COOKIE_ATTRIBUTES.has(cookieName.toLowerCase())) continue;
      names.add(cookieName);
    }
  }
  return [...names].sort();
}

function parseEvidenceId(evidenceId: string): string | undefined {
  const trimmed = evidenceId.trim();
  const hex = trimmed.startsWith(EVIDENCE_ID_PREFIX)
    ? trimmed.slice(EVIDENCE_ID_PREFIX.length)
    : trimmed;
  if (!HASH_PATTERN.test(hex)) return undefined;
  return hex.toLowerCase();
}

function hashArtifact(artifact: {
  version: 1;
  request: EvidenceRequest;
  response: EvidenceResponse;
}): string {
  return createHash("sha256").update(JSON.stringify(artifact)).digest("hex");
}

/**
 * Local, content-addressed evidence store. Artifacts are sanitized before they
 * touch disk, hashed with SHA-256, and size-capped. The store never uploads
 * anything and never writes secrets in the clear.
 */
export class EvidenceStore {
  private readonly rootDir: string;
  private readonly maxArtifactBytes: number;
  private readonly now: () => Date;

  constructor(options: EvidenceStoreOptions) {
    this.rootDir = options.rootDir;
    this.maxArtifactBytes = options.maxArtifactBytes ?? DEFAULT_MAX_ARTIFACT_BYTES;
    this.now = options.now ?? (() => new Date());
  }

  async capture(input: CaptureInput, options: { redact?: boolean } = {}): Promise<CaptureResult> {
    const redact = options.redact ?? true;
    const requestHeaders = input.request.headers ?? {};
    const responseHeaders = input.response.headers ?? {};

    const request: EvidenceRequest = {
      method: input.request.method.toUpperCase(),
      url: redact ? redactUrl(input.request.url) : input.request.url,
      headers: redact ? redactHeaders(requestHeaders, false) : { ...requestHeaders },
      body: redact
        ? redactBody(input.request.body, requestHeaders["content-type"] ?? "")
        : input.request.body,
    };
    const response: EvidenceResponse = {
      status: input.response.status,
      statusText: input.response.statusText ?? "",
      headers: redact ? redactHeaders(responseHeaders, true) : { ...responseHeaders },
      body: redact
        ? redactBody(input.response.body, responseHeaders["content-type"] ?? "")
        : input.response.body,
      bodyBytes:
        input.response.bodyBytes ??
        (input.response.body === undefined ? 0 : byteLength(input.response.body)),
      truncated: input.response.truncated ?? false,
      durationMs: input.response.durationMs ?? 0,
    };

    const content = { version: 1 as const, request, response };
    const sha256 = hashArtifact(content);
    const artifact: EvidenceArtifact = {
      ...content,
      id: `${EVIDENCE_ID_PREFIX}${sha256}`,
      sha256,
      createdAt: this.now().toISOString(),
      sizeBytes: 0,
    };

    let serialized: string;
    try {
      serialized = JSON.stringify(artifact);
    } catch {
      return { ok: false, error: "evidence artifact is not serializable" };
    }
    const sizeBytes = byteLength(serialized);
    if (sizeBytes > this.maxArtifactBytes) {
      return {
        ok: false,
        error: `evidence artifact is ${sizeBytes} bytes, exceeding the ${this.maxArtifactBytes}-byte cap`,
      };
    }
    artifact.sizeBytes = sizeBytes;
    serialized = JSON.stringify(artifact);

    const relativePath = `artifacts/${sha256}.json`;
    const absolutePath = join(this.rootDir, "artifacts", `${sha256}.json`);
    await mkdir(dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, serialized, "utf8");

    return {
      ok: true,
      evidenceId: artifact.id,
      sha256,
      path: relativePath,
      sizeBytes,
    };
  }

  async get(evidenceId: string): Promise<EvidenceArtifact | undefined> {
    const hex = parseEvidenceId(evidenceId);
    if (hex === undefined) return undefined;

    let raw: string;
    try {
      raw = await readFile(join(this.rootDir, "artifacts", `${hex}.json`), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }

    let artifact: EvidenceArtifact;
    try {
      artifact = JSON.parse(raw) as EvidenceArtifact;
    } catch {
      return undefined;
    }
    if (artifact.sha256 !== hex) return undefined;
    if (
      hashArtifact({
        version: artifact.version,
        request: artifact.request,
        response: artifact.response,
      }) !== hex
    ) {
      return undefined;
    }
    return artifact;
  }

  async verify(evidenceId: string): Promise<boolean> {
    return (await this.get(evidenceId)) !== undefined;
  }

  async compare(candidateId: string, baselineId: string): Promise<CompareResult> {
    const candidate = await this.get(candidateId);
    if (candidate === undefined) {
      return { ok: false, error: `candidate evidence not found or invalid: ${candidateId}` };
    }
    const baseline = await this.get(baselineId);
    if (baseline === undefined) {
      return { ok: false, error: `baseline evidence not found or invalid: ${baselineId}` };
    }

    const headerNames = [
      ...new Set([
        ...Object.keys(candidate.response.headers),
        ...Object.keys(baseline.response.headers),
      ]),
    ].sort();
    const headers: EvidenceHeaderDiff[] = [];
    for (const name of headerNames) {
      const candidateValue = candidate.response.headers[name];
      const baselineValue = baseline.response.headers[name];
      if (candidateValue !== baselineValue) {
        headers.push({ name, candidate: candidateValue, baseline: baselineValue });
      }
    }

    const candidateBody = candidate.response.body ?? "";
    const baselineBody = baseline.response.body ?? "";
    const candidateSha256 = createHash("sha256").update(candidateBody).digest("hex");
    const baselineSha256 = createHash("sha256").update(baselineBody).digest("hex");

    return {
      ok: true,
      comparison: {
        candidateId: candidate.id,
        baselineId: baseline.id,
        status: {
          candidate: candidate.response.status,
          baseline: baseline.response.status,
          changed: candidate.response.status !== baseline.response.status,
        },
        headers,
        body: {
          changed: candidateSha256 !== baselineSha256,
          candidateBytes: byteLength(candidateBody),
          baselineBytes: byteLength(baselineBody),
          candidateSha256,
          baselineSha256,
        },
      },
    };
  }

  async parse(evidenceId: string): Promise<ParseResult> {
    const artifact = await this.get(evidenceId);
    if (artifact === undefined) {
      return { ok: false, error: `evidence not found or invalid: ${evidenceId}` };
    }

    const pageUrl = artifact.request.url;
    const parsed = parseHtmlPage(pageUrl, artifact.response.body ?? "", artifact.response.headers);
    const resolveBase = parsed.baseUrl ?? pageUrl;

    const forms: CrawledForm[] = [];
    for (const form of parsed.forms) {
      const action = normalizeUrl(form.action, resolveBase);
      if (action === undefined) continue;
      forms.push({
        pageUrl,
        action,
        method: form.method,
        parameters: form.parameters,
      });
    }

    const assets: CrawledAsset[] = [];
    const seenAssets = new Set<string>();
    for (const asset of parsed.assets) {
      const url = normalizeUrl(asset.url, resolveBase);
      if (url === undefined || seenAssets.has(url)) continue;
      seenAssets.add(url);
      assets.push({ url, type: asset.type });
    }

    const links: string[] = [];
    const seenLinks = new Set<string>();
    for (const link of parsed.links) {
      const url = normalizeUrl(link, resolveBase);
      if (url === undefined || seenLinks.has(url)) continue;
      seenLinks.add(url);
      links.push(url);
    }

    return {
      ok: true,
      facts: {
        evidenceId: artifact.id,
        url: pageUrl,
        status: artifact.response.status,
        headers: artifact.response.headers,
        cookies: parseCookieNames(artifact.response.headers),
        forms,
        assets,
        links,
        technologies: parsed.technologies,
      },
    };
  }
}
