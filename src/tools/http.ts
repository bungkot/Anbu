import { readEnv } from "../config.js";
import type { AuditLog } from "../audit/log.js";
import { evaluateGuard } from "../guardrails/index.js";
import type { GuardResult } from "../guardrails/index.js";
import { findMatchingTarget } from "../guardrails/scope.js";
import type { RateLimiter } from "../guardrails/rate-limit.js";
import type { Scope } from "../model/scope.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Headers that must not survive a cross-host redirect. The authorization token
 * is resolved from the environment and must never leak to another origin.
 */
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "x-api-key",
  "x-auth-token",
]);

const decoder = new TextDecoder("utf-8");

export interface HttpRequestInput {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

export interface HttpResponseSummary {
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  /** Decoded, size-capped body. Never render directly into the model context. */
  bodyText: string;
  /** Actual received body size in bytes, even when `bodyText` was truncated. */
  bodyBytes: number;
  truncated: boolean;
  durationMs: number;
}

export interface RedirectRecord {
  from: string;
  status: number;
  location: string;
  followed: boolean;
  reason?: string;
}

export interface HttpRequestOutcome {
  ok: boolean;
  method: string;
  url: string;
  response?: HttpResponseSummary;
  redirects: RedirectRecord[];
  guard?: GuardResult;
  /** Safe, non-sensitive explanation for a blocked or failed request. */
  error?: string;
  requiresApproval?: boolean;
}

export interface GuardedHttpClientOptions {
  scope: Scope;
  rateLimiter: RateLimiter;
  audit: AuditLog;
  now?: () => Date;
  env?: (name: string) => string | undefined;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  maxResponseBodyBytes?: number;
}

function normalizeHeaders(headers?: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};
  if (headers === undefined) return normalized;
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function stripSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
  const remaining: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SENSITIVE_HEADERS.has(key)) remaining[key] = value;
  }
  return remaining;
}

function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function resolveLocation(from: string, location: string): string | undefined {
  try {
    return new URL(location, from).toString();
  } catch {
    return undefined;
  }
}

function redirectSemantics(
  method: string,
  body: string | Uint8Array | undefined,
  status: number,
): { method: string; body: string | Uint8Array | undefined } {
  // 303 always switches to GET; 301/302 historically switch POST to GET.
  // 307/308 preserve the method and body.
  if (status === 303) return { method: "GET", body: undefined };
  if ((status === 301 || status === 302) && method === "POST") {
    return { method: "GET", body: undefined };
  }
  return { method, body };
}

/** Copy into a fresh ArrayBuffer so the body is a valid, non-generic BodyInit. */
function toBodyInit(body: string | Uint8Array | undefined): BodyInit | undefined {
  if (body === undefined) return undefined;
  if (typeof body === "string") return body;
  const copy = new Uint8Array(body.byteLength);
  copy.set(body);
  return copy.buffer;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === undefined ? `request failed: ${err.message}` : `request failed (${code})`;
  }
  return "request failed";
}

/**
 * The only HTTP client the tool layer may use. Every request, including every
 * redirect hop, passes through the guardrail chain before it is sent. A blocked
 * request never reaches `fetch`.
 */
export class GuardedHttpClient {
  private readonly scope: Scope;
  private readonly rateLimiter: RateLimiter;
  private readonly audit: AuditLog;
  private readonly now: () => Date;
  private readonly env: (name: string) => string | undefined;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxResponseBodyBytes: number;

  constructor(options: GuardedHttpClientOptions) {
    this.scope = options.scope;
    this.rateLimiter = options.rateLimiter;
    this.audit = options.audit;
    this.now = options.now ?? (() => new Date());
    this.env = options.env ?? readEnv;
    this.fetchFn = options.fetchFn ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxResponseBodyBytes = options.maxResponseBodyBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  }

  async request(input: HttpRequestInput): Promise<HttpRequestOutcome> {
    let method = input.method.toUpperCase();
    let url = input.url;
    let headers = normalizeHeaders(input.headers);
    let body = input.body;

    const redirects: RedirectRecord[] = [];
    const visited = new Set<string>([url]);
    let lastResponse: HttpResponseSummary | undefined;
    const startedAt = this.now().getTime();

    const maxRedirects = this.scope.policy?.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    const followExternal = this.scope.policy?.followExternalRedirects ?? false;

    for (let hop = 0; ; hop++) {
      const guard = await evaluateGuard(
        {
          scope: this.scope,
          rateLimiter: this.rateLimiter,
          audit: this.audit,
          now: this.now(),
          env: this.env,
        },
        { method, url, body },
      );

      if (!guard.allowed) {
        return {
          ok: false,
          method,
          url,
          response: lastResponse,
          redirects,
          guard,
          error: guard.reason ?? "request blocked by guardrails",
          requiresApproval: guard.requiresApproval,
        };
      }

      let response: Response;
      try {
        response = await this.fetchFn(url, {
          method,
          headers,
          body: toBodyInit(body),
          redirect: "manual",
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err) {
        return {
          ok: false,
          method,
          url,
          response: lastResponse,
          redirects,
          error: errorMessage(err),
        };
      }

      const summary = await this.readResponse(response, url, startedAt);
      lastResponse = summary;

      const location = response.headers.get("location");
      if (!REDIRECT_STATUSES.has(response.status) || location === null) {
        return { ok: true, method, url, response: summary, redirects };
      }

      const resolved = resolveLocation(url, location);
      if (resolved === undefined) {
        return {
          ok: true,
          method,
          url,
          response: summary,
          redirects,
          error: "redirect location is invalid",
        };
      }

      if (hop >= maxRedirects) {
        redirects.push({
          from: url,
          status: response.status,
          location: resolved,
          followed: false,
          reason: "max redirects exceeded",
        });
        return { ok: true, method, url, response: summary, redirects };
      }

      if (visited.has(resolved)) {
        redirects.push({
          from: url,
          status: response.status,
          location: resolved,
          followed: false,
          reason: "redirect loop detected",
        });
        return { ok: true, method, url, response: summary, redirects };
      }

      const target = findMatchingTarget(this.scope, new URL(resolved));
      if (target === undefined && !followExternal) {
        redirects.push({
          from: url,
          status: response.status,
          location: resolved,
          followed: false,
          reason: "external redirect is out of scope and followExternalRedirects is false",
        });
        return { ok: true, method, url, response: summary, redirects };
      }

      const next = redirectSemantics(method, body, response.status);
      if (new URL(url).host !== new URL(resolved).host) {
        headers = stripSensitiveHeaders(headers);
      }
      redirects.push({ from: url, status: response.status, location: resolved, followed: true });
      visited.add(resolved);
      url = resolved;
      method = next.method;
      body = next.body;
    }
  }

  private async readResponse(
    response: Response,
    url: string,
    startedAt: number,
  ): Promise<HttpResponseSummary> {
    const stream = response.body;
    if (stream === null) {
      return {
        url,
        status: response.status,
        statusText: response.statusText,
        headers: headersToObject(response.headers),
        bodyText: "",
        bodyBytes: 0,
        truncated: false,
        durationMs: this.now().getTime() - startedAt,
      };
    }

    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    let truncated = false;

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value === undefined) continue;
        received += value.byteLength;
        if (received > this.maxResponseBodyBytes) {
          const keep = this.maxResponseBodyBytes - (received - value.byteLength);
          if (keep > 0) chunks.push(value.slice(0, keep));
          truncated = true;
          break;
        }
        chunks.push(value);
      }
    } finally {
      if (truncated) {
        await reader.cancel().catch(() => undefined);
      } else {
        reader.releaseLock();
      }
    }

    let text = "";
    if (chunks.length === 1) {
      text = decoder.decode(chunks[0], { stream: false });
    } else if (chunks.length > 1) {
      const merged = new Uint8Array(this.maxResponseBodyBytes);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.byteLength;
      }
      text = decoder.decode(merged.subarray(0, offset), { stream: false });
    }

    return {
      url,
      status: response.status,
      statusText: response.statusText,
      headers: headersToObject(response.headers),
      bodyText: text,
      bodyBytes: received,
      truncated,
      durationMs: this.now().getTime() - startedAt,
    };
  }
}
