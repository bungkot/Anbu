import type { Authorization } from "../model/scope.js";

export interface AuthorizationStatus {
  ok: boolean;
  reason?: string;
  reference?: string;
  expiresAt?: string;
}

/**
 * Resolve an authorization token reference. `env:NAME` reads from the supplied
 * environment; anything else is treated as a literal token. The resolved value
 * is never returned or logged.
 */
export function resolveToken(
  reference: string,
  env: (name: string) => string | undefined,
): string | undefined {
  if (reference.startsWith("env:")) {
    const name = reference.slice(4);
    const value = env(name);
    return value !== undefined && value.length > 0 ? value : undefined;
  }
  return reference.length > 0 ? reference : undefined;
}

export function validateAuthorization(
  authorization: Authorization,
  now: Date = new Date(),
  env: (name: string) => string | undefined = (name) => process.env[name],
): AuthorizationStatus {
  const validFrom = Date.parse(authorization.validFrom);
  const validUntil = Date.parse(authorization.validUntil);
  if (Number.isNaN(validFrom) || Number.isNaN(validUntil)) {
    return { ok: false, reason: "authorization dates are invalid" };
  }
  const nowMs = now.getTime();
  if (nowMs < validFrom) {
    return { ok: false, reason: "authorization is not yet valid" };
  }
  if (nowMs > validUntil) {
    return { ok: false, reason: "authorization has expired" };
  }
  const token = resolveToken(authorization.token, env);
  if (token === undefined) {
    return { ok: false, reason: "authorization token is missing or empty" };
  }
  return {
    ok: true,
    reference: authorization.reference,
    expiresAt: authorization.validUntil,
  };
}
