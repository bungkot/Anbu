import { isIP } from "node:net";
import type { DenyEntry, HttpMethod, Scope, Target } from "../model/scope.js";
import { READ_ONLY_METHODS, cidrContains, parseCidr } from "../model/scope.js";
import type { GuardDecision, GuardRequest } from "./types.js";

/** Host matching supports exact hosts, IP literals, and `*.example.com`. */
export function hostMatches(pattern: string, host: string): boolean {
  const normalizedPattern = pattern.toLowerCase().replace(/\.$/, "");
  const normalizedHost = host.toLowerCase().replace(/\.$/, "");
  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1);
    return normalizedHost.length > suffix.length && normalizedHost.endsWith(suffix);
  }
  return normalizedPattern === normalizedHost;
}

/** Path prefix matching. `/` matches everything; `/app` matches `/app` and `/app/*`. */
export function pathMatches(prefix: string, path: string): boolean {
  if (prefix === "" || prefix === "/") return path.startsWith("/");
  const normalized = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return path === normalized || path.startsWith(`${normalized}/`);
}

function parseUrl(raw: string): URL | undefined {
  try {
    return new URL(raw);
  } catch {
    return undefined;
  }
}

function defaultPort(scheme: "http" | "https"): number {
  return scheme === "http" ? 80 : 443;
}

export function findMatchingTarget(scope: Scope, url: URL): Target | undefined {
  for (const target of scope.targets) {
    if (!hostMatches(target.host, url.hostname)) continue;
    const scheme = target.scheme ?? (target.port === 80 ? "http" : "https");
    if (scheme !== (url.protocol === "http:" ? "http" : "https")) continue;
    const expectedPort = target.port ?? defaultPort(scheme);
    const actualPort =
      url.port === "" ? defaultPort(url.protocol === "http:" ? "http" : "https") : Number(url.port);
    if (expectedPort !== actualPort) continue;
    if (
      target.paths !== undefined &&
      target.paths.length > 0 &&
      !target.paths.some((prefix) => pathMatches(prefix, url.pathname))
    ) {
      continue;
    }
    return target;
  }
  return undefined;
}

function matchDeny(deny: DenyEntry[], url: URL): string | undefined {
  for (const entry of deny) {
    if ("cidr" in entry) {
      const cidr = parseCidr(entry.cidr);
      if (cidr !== undefined && isIP(url.hostname) !== 0 && cidrContains(cidr, url.hostname)) {
        return entry.cidr;
      }
      continue;
    }
    if (!hostMatches(entry.host, url.hostname)) continue;
    if (
      entry.paths !== undefined &&
      entry.paths.length > 0 &&
      !entry.paths.some((prefix) => pathMatches(prefix, url.pathname))
    ) {
      continue;
    }
    return entry.host;
  }
  return undefined;
}

/**
 * Scope allowlist + deny list + method check. This is the first guardrail a
 * request passes through; a denial here means no network call is made.
 */
export function evaluateScope(scope: Scope, request: GuardRequest): GuardDecision {
  const url = parseUrl(request.url);
  if (url === undefined) {
    return { allowed: false, reason: "request URL is invalid" };
  }
  const target = findMatchingTarget(scope, url);
  if (target === undefined) {
    return { allowed: false, reason: "URL is not covered by any in-scope target" };
  }
  const denyReason = matchDeny(scope.deny, url);
  if (denyReason !== undefined) {
    return { allowed: false, reason: `URL matches a deny rule (${denyReason})` };
  }
  const method = request.method.toUpperCase() as HttpMethod;
  const allowedMethods = scope.readOnly ? READ_ONLY_METHODS : (target.methods ?? READ_ONLY_METHODS);
  if (!allowedMethods.includes(method)) {
    return { allowed: false, reason: `method ${request.method} is not allowed for this target` };
  }
  return { allowed: true, target };
}
