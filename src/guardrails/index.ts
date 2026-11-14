import type { Target } from "../model/scope.js";
import type { AuditLog } from "../audit/log.js";
import type { Scope } from "../model/scope.js";
import { validateAuthorization } from "./authorization.js";
import { evaluatePolicy } from "./policy.js";
import { evaluateScope } from "./scope.js";
import type { RateLimiter } from "./rate-limit.js";
import type { GuardRequest } from "./types.js";

export interface GuardCheck {
  name: "scope" | "authorization" | "policy" | "rate-limit";
  allowed: boolean;
  reason?: string;
  requiresApproval?: boolean;
}

export interface GuardResult {
  allowed: boolean;
  checks: GuardCheck[];
  reason?: string;
  requiresApproval?: boolean;
  target?: Target;
}

export interface GuardContext {
  scope: Scope;
  rateLimiter: RateLimiter;
  audit: AuditLog;
  now?: Date;
  env?: (name: string) => string | undefined;
}

/** Audit targets never include query strings or fragments. */
function sanitizeTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/**
 * The single entry point for every outbound request. It runs the guardrail
 * chain in order and writes one audit entry. A denied request is never sent.
 */
export async function evaluateGuard(
  ctx: GuardContext,
  request: GuardRequest,
): Promise<GuardResult> {
  const checks: GuardCheck[] = [];
  const now = ctx.now ?? new Date();
  const env = ctx.env ?? ((name: string) => process.env[name]);

  const scopeDecision = evaluateScope(ctx.scope, request);
  checks.push({
    name: "scope",
    allowed: scopeDecision.allowed,
    reason: scopeDecision.allowed ? undefined : scopeDecision.reason,
    requiresApproval: scopeDecision.allowed ? undefined : scopeDecision.requiresApproval,
  });
  if (!scopeDecision.allowed) return finish("deny");

  const authorization = validateAuthorization(ctx.scope.authorization, now, env);
  checks.push({
    name: "authorization",
    allowed: authorization.ok,
    reason: authorization.reason,
  });
  if (!authorization.ok) return finish("deny");

  const policyDecision = evaluatePolicy(ctx.scope, request);
  checks.push({
    name: "policy",
    allowed: policyDecision.allowed,
    reason: policyDecision.allowed ? undefined : policyDecision.reason,
    requiresApproval: policyDecision.allowed ? undefined : policyDecision.requiresApproval,
  });
  if (!policyDecision.allowed) return finish("deny");

  const rateDecision = ctx.rateLimiter.tryAcquire(hostOf(request.url), now.getTime());
  checks.push({
    name: "rate-limit",
    allowed: rateDecision.allowed,
    reason: rateDecision.reason,
  });
  if (!rateDecision.allowed) return finish("deny");

  return finish("allow");

  async function finish(decision: "allow" | "deny"): Promise<GuardResult> {
    const failed = checks.find((check) => !check.allowed);
    const result: GuardResult = {
      allowed: decision === "allow",
      checks,
      reason: failed?.reason,
      requiresApproval: failed?.requiresApproval,
      target: scopeDecision.allowed ? scopeDecision.target : undefined,
    };
    await ctx.audit.append("guardrail", {
      decision,
      reason: result.reason,
      method: request.method.toUpperCase(),
      target: sanitizeTarget(request.url),
    });
    return result;
  }
}
