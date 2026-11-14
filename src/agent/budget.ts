import { config } from "../config.js";
import type { RateLimiter } from "../guardrails/rate-limit.js";
import type { BudgetStatus } from "../model/report.js";
import type { OwaspCategory, Scope } from "../model/scope.js";
import { OWASP_CATEGORIES } from "../model/scope.js";

/** Runtime budgets for one pentest run. The scope document overrides the defaults. */
export interface BudgetLimits {
  maxRequests: number;
  maxDurationMinutes: number;
  maxModelTurns: number;
  maxFindingsPerCategory: number;
  maxBodyBytes: number;
  maxRedirects: number;
}

export type StopReason =
  | "completed"
  | "budget_exhausted"
  | "guardrail_streak"
  | "tool_failure_streak"
  | "planner_halt"
  | "human_stop"
  | "model_unavailable";

const ZERO_FINDINGS = Object.fromEntries(
  OWASP_CATEGORIES.map((category) => [category, 0]),
) as Record<OwaspCategory, number>;

/** Resolve the effective budgets from the scope policy, falling back to config. */
export function resolveBudgetLimits(scope: Scope): BudgetLimits {
  const policy = scope.policy;
  return {
    maxRequests: policy?.maxRequests ?? config.maxRequests,
    maxDurationMinutes: policy?.maxDurationMinutes ?? config.maxDurationMinutes,
    maxModelTurns: policy?.maxModelTurns ?? config.maxModelTurns,
    maxFindingsPerCategory: policy?.maxFindingsPerCategory ?? config.maxFindingsPerCategory,
    maxBodyBytes: policy?.maxBodyBytes ?? config.maxBodyBytes,
    maxRedirects: policy?.maxRedirects ?? config.maxRedirects,
  };
}

/**
 * Tracks the mutable parts of a run budget. The global request count is owned by
 * the rate limiter, so request accounting stays in one place.
 */
export class RunBudget {
  private readonly limits: BudgetLimits;
  private readonly rateLimiter: RateLimiter;
  private readonly now: () => Date;
  private readonly startedAt: number;
  private modelTurns = 0;
  private stopped: StopReason | undefined;
  private readonly findingsByCategory: Record<OwaspCategory, number> = { ...ZERO_FINDINGS };

  constructor(options: { limits: BudgetLimits; rateLimiter: RateLimiter; now?: () => Date }) {
    this.limits = options.limits;
    this.rateLimiter = options.rateLimiter;
    this.now = options.now ?? (() => new Date());
    this.startedAt = this.now().getTime();
  }

  get stopReason(): StopReason | undefined {
    return this.stopped;
  }

  get remainingRequests(): number {
    return this.rateLimiter.remainingGlobal;
  }

  get remainingModelTurns(): number {
    return Math.max(0, this.limits.maxModelTurns - this.modelTurns);
  }

  get remainingMinutes(): number {
    const elapsedMs = this.now().getTime() - this.startedAt;
    return Math.max(0, this.limits.maxDurationMinutes - elapsedMs / 60_000);
  }

  recordModelTurn(): void {
    this.modelTurns += 1;
  }

  /** The reason the budget is exhausted, or undefined while work can continue. */
  exhaustedReason(): StopReason | undefined {
    if (this.stopped !== undefined) return this.stopped;
    if (this.remainingRequests <= 0) return "budget_exhausted";
    if (this.remainingModelTurns <= 0) return "budget_exhausted";
    if (this.remainingMinutes <= 0) return "budget_exhausted";
    return undefined;
  }

  /** Record one finding; returns false when the per-category cap is reached. */
  recordFinding(category: OwaspCategory): boolean {
    if (this.findingsByCategory[category] >= this.limits.maxFindingsPerCategory) return false;
    this.findingsByCategory[category] += 1;
    return true;
  }

  findingsCount(category: OwaspCategory): number {
    return this.findingsByCategory[category];
  }

  stop(reason: StopReason): void {
    if (this.stopped === undefined) this.stopped = reason;
  }

  status(): BudgetStatus {
    return {
      maxRequests: this.limits.maxRequests,
      usedRequests: this.limits.maxRequests - this.remainingRequests,
      maxDurationMinutes: this.limits.maxDurationMinutes,
      elapsedMinutes: (this.now().getTime() - this.startedAt) / 60_000,
      maxModelTurns: this.limits.maxModelTurns,
      usedModelTurns: this.modelTurns,
    };
  }
}
