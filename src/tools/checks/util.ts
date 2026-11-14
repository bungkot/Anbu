import { isStateChangingMethod } from "../../guardrails/policy.js";
import type { Finding } from "../../model/finding.js";
import type {
  CandidateFinding,
  CheckCaptureRequest,
  CheckCaptureResponse,
  CheckContext,
  CheckFetchInput,
  CheckResponse,
  CheckResult,
  CheckMetadata,
  EvidenceRef,
} from "./types.js";
import { checkResult, makeFinding } from "./types.js";

export function headerValue(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value;
  }
  return undefined;
}

/** All values for a header name. `set-cookie` may appear more than once. */
export function headerValues(
  headers: Record<string, string>,
  name: string,
): string[] {
  const lower = name.toLowerCase();
  const values: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) values.push(value);
  }
  return values;
}

export function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

export function isRedirectStatus(status: number): boolean {
  return status >= 300 && status < 400;
}

export function isReadOnlyMethod(method: string): boolean {
  return !isStateChangingMethod(method);
}

export function normalizeMethod(method: string | undefined, fallback = "GET"): string {
  const normalized = (method ?? fallback).trim().toUpperCase();
  return normalized.length > 0 ? normalized : fallback;
}

export function readOptionString(
  options: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = options?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function readOptionNumber(
  options: Record<string, unknown> | undefined,
  key: string,
  fallback: number,
): number {
  const value = options?.[key];
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return value;
}

export function readOptionBoolean(
  options: Record<string, unknown> | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const value = options?.[key];
  return typeof value === "boolean" ? value : fallback;
}

export function readOptionStringArray(
  options: Record<string, unknown> | undefined,
  key: string,
): string[] | undefined {
  const value = options?.[key];
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((item): item is string => typeof item === "string");
  return items.length > 0 ? items : undefined;
}

export function readOptionRecord(
  options: Record<string, unknown> | undefined,
  key: string,
): Record<string, unknown> | undefined {
  const value = options?.[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

export function readRecordString(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

export function readRecordBoolean(
  record: Record<string, unknown>,
  key: string,
): boolean | undefined {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

export function readRecordNumber(
  record: Record<string, unknown>,
  key: string,
): number | undefined {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function parseJsonBody(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

export interface ParsedCookie {
  name: string;
  value: string;
  /** Lower-cased attribute name to value. Valueless attributes are "". */
  attributes: Record<string, string>;
}

/**
 * Parse a `Set-Cookie` header value. Multiple cookies are split on a comma
 * that is followed by another `name=value` pair, so commas inside `Expires`
 * dates do not split incorrectly.
 */
export function parseSetCookieHeader(value: string): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];
  for (const part of value.split(/,(?=\s*[^;,=\s]+\s*=)/)) {
    const segments = part
      .split(";")
      .map((segment) => segment.trim())
      .filter((segment) => segment.length > 0);
    if (segments.length === 0) continue;
    const first = segments[0];
    const equals = first.indexOf("=");
    if (equals <= 0) continue;
    const attributes: Record<string, string> = {};
    for (const segment of segments.slice(1)) {
      const attrEquals = segment.indexOf("=");
      if (attrEquals <= 0) {
        attributes[segment.toLowerCase()] = "";
      } else {
        attributes[segment.slice(0, attrEquals).trim().toLowerCase()] = segment
          .slice(attrEquals + 1)
          .trim();
      }
    }
    cookies.push({
      name: first.slice(0, equals).trim(),
      value: first.slice(equals + 1).trim(),
      attributes,
    });
  }
  return cookies;
}

export function cookiesFromHeaders(headers: Record<string, string>): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];
  for (const value of headerValues(headers, "set-cookie")) {
    cookies.push(...parseSetCookieHeader(value));
  }
  return cookies;
}

/** Set or replace a query parameter, preserving the rest of the URL. */
export function withQuery(url: string, parameter: string, value: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set(parameter, value);
  return parsed.toString();
}

/** Audit targets never include query strings or fragments. */
export function safeAuditTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

/** Fetch the primary request for a check and return a safe error. */
export async function fetchPrimary(
  ctx: CheckContext,
  input: { method?: string; url: string; headers?: Record<string, string>; body?: string },
): Promise<{ response?: CheckResponse; request?: CheckFetchInput; error?: string }> {
  const method = normalizeMethod(input.method);
  const result = await ctx.fetch({
    method,
    url: input.url,
    headers: input.headers,
    body: input.body,
  });
  return { response: result.response, request: result.request, error: result.error };
}

export async function captureResponse(
  ctx: CheckContext,
  request: CheckFetchInput,
  response: CheckResponse,
): Promise<EvidenceRef | undefined> {
  const captureRequest: CheckCaptureRequest = {
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: request.body,
  };
  const captureResponse: CheckCaptureResponse = {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    body: response.bodyText,
    bodyBytes: response.bodyBytes,
    truncated: response.truncated,
    durationMs: response.durationMs,
  };
  return ctx.capture(captureRequest, captureResponse);
}

/** Convert candidates into findings that share the captured evidence. */
export function materialize(
  metadata: CheckMetadata,
  candidates: readonly CandidateFinding[],
  evidence: readonly EvidenceRef[],
): Finding[] {
  return candidates.map((candidate) => makeFinding(metadata, candidate, evidence));
}

/** Convenience result builder for checks that captured evidence. */
export function responseResult(
  ctx: CheckContext,
  findings: Finding[],
  evidence: EvidenceRef[],
  error?: string,
): CheckResult {
  return checkResult(ctx, findings, evidence, error);
}

/** Capture several request/response pairs, skipping any the store refuses. */
export async function captureAll(
  ctx: CheckContext,
  pairs: ReadonlyArray<{ request: CheckFetchInput; response: CheckResponse }>,
): Promise<EvidenceRef[]> {
  const evidence: EvidenceRef[] = [];
  for (const pair of pairs) {
    const captured = await captureResponse(ctx, pair.request, pair.response);
    if (captured !== undefined) evidence.push(captured);
  }
  return evidence;
}

/** Return the first pattern that matches the body, if any. */
export function firstMatch(
  body: string,
  patterns: readonly RegExp[],
): RegExpMatchArray | undefined {
  for (const pattern of patterns) {
    const match = pattern.exec(body);
    if (match !== null) return match;
  }
  return undefined;
}

/** True when the status is a client- or server-side error. */
export function isErrorStatus(status: number): boolean {
  return status >= 400;
}

/** True when the status is an authentication/authorization failure. */
export function isAuthFailureStatus(status: number): boolean {
  return status === 401 || status === 403;
}

/** True when the status means the method is not supported. */
export function isMethodNotAllowed(status: number): boolean {
  return status === 405;
}
