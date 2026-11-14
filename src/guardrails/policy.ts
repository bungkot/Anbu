import type { Scope } from "../model/scope.js";
import type { GuardDecision, GuardRequest } from "./types.js";

export const STATE_CHANGING_METHODS: readonly string[] = ["POST", "PUT", "PATCH", "DELETE"];

export function isStateChangingMethod(method: string): boolean {
  return STATE_CHANGING_METHODS.includes(method.toUpperCase());
}

function bodyByteLength(body: string | Uint8Array | undefined): number {
  if (body === undefined) return 0;
  return typeof body === "string" ? Buffer.byteLength(body, "utf8") : body.byteLength;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return "/";
  }
}

function matchesAllowEntry(entry: string, method: string, path: string): boolean {
  const space = entry.indexOf(" ");
  if (space <= 0) return false;
  const entryMethod = entry.slice(0, space).toUpperCase();
  const entryPath = entry.slice(space + 1);
  const normalized = entryPath.endsWith("/") ? entryPath.slice(0, -1) : entryPath;
  return entryMethod === method && (path === normalized || path.startsWith(`${normalized}/`));
}

/**
 * Method, body-size, read-only, and state-changing policy. This runs after the
 * scope check and before the rate limiter.
 */
export function evaluatePolicy(scope: Scope, request: GuardRequest): GuardDecision {
  const method = request.method.toUpperCase();
  const bodyBytes = request.bodyBytes ?? bodyByteLength(request.body);
  const maxBodyBytes = scope.policy?.maxBodyBytes ?? 65_536;
  if (bodyBytes > maxBodyBytes) {
    return {
      allowed: false,
      reason: `request body ${bodyBytes} bytes exceeds policy maxBodyBytes ${maxBodyBytes}`,
    };
  }

  if (!isStateChangingMethod(method)) {
    return { allowed: true };
  }

  if (scope.readOnly) {
    return { allowed: false, reason: `read-only scope blocks state-changing method ${method}` };
  }

  const stateChanging = scope.stateChanging;
  const mode = stateChanging?.mode ?? "deny";
  if (mode === "deny") {
    return { allowed: false, reason: `state-changing method ${method} is denied by policy` };
  }
  if (mode === "approve") {
    return {
      allowed: false,
      reason: `state-changing method ${method} requires human approval`,
      requiresApproval: true,
    };
  }

  const path = safePath(request.url);
  const permitted = (stateChanging?.allow ?? []).some((entry) =>
    matchesAllowEntry(entry, method, path),
  );
  if (!permitted) {
    return {
      allowed: false,
      reason: `state-changing method ${method} is not in stateChanging.allow`,
    };
  }
  return { allowed: true };
}
