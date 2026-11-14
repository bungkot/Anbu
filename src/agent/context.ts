import type { AuditLog } from "../audit/log.js";
import type { RateLimiter } from "../guardrails/rate-limit.js";
import type { Finding } from "../model/finding.js";
import type { OwaspCategory, Scope } from "../model/scope.js";
import type { AttackSurfaceSummary } from "../recon.js";
import type { EvidenceStore } from "../store/evidence-store.js";
import type { GuardedHttpClient } from "../tools/http.js";
import type { BudgetLimits, StopReason } from "./budget.js";
import { RunBudget } from "./budget.js";

/** Bounded working memory for the planner. Only summaries ever enter a prompt. */
export const MAX_RECENT_RESULTS = 20;

export interface ToolResultSummary {
  tool: string;
  ok: boolean;
  url?: string;
  status?: number;
  evidenceId?: string;
  error?: string;
  detail?: string;
}

export interface RunContextOptions {
  runId: string;
  scope: Scope;
  limits: BudgetLimits;
  rateLimiter: RateLimiter;
  audit: AuditLog;
  store: EvidenceStore;
  client: GuardedHttpClient;
  attackSurface?: AttackSurfaceSummary;
  now?: () => Date;
  objective?: string;
}

/**
 * Mutable state for one pentest run: budgets, findings, working memory, and the
 * shared tool-layer collaborators. The loop is the only writer.
 */
export class RunContext {
  readonly runId: string;
  readonly scope: Scope;
  readonly limits: BudgetLimits;
  readonly rateLimiter: RateLimiter;
  readonly audit: AuditLog;
  readonly store: EvidenceStore;
  readonly client: GuardedHttpClient;
  readonly budget: RunBudget;
  readonly now: () => Date;
  readonly startedAt: number;
  objective: string;
  attackSurface: AttackSurfaceSummary | undefined;
  readonly findings: Finding[] = [];
  readonly recentResults: ToolResultSummary[] = [];
  readonly executedChecks = new Set<string>();
  readonly executedCategories = new Set<OwaspCategory>();
  stopReason: StopReason | undefined;
  modelAvailable = true;

  constructor(options: RunContextOptions) {
    this.runId = options.runId;
    this.scope = options.scope;
    this.limits = options.limits;
    this.rateLimiter = options.rateLimiter;
    this.audit = options.audit;
    this.store = options.store;
    this.client = options.client;
    this.now = options.now ?? (() => new Date());
    this.startedAt = this.now().getTime();
    this.objective = options.objective ?? "";
    this.attackSurface = options.attackSurface;
    this.budget = new RunBudget({
      limits: options.limits,
      rateLimiter: options.rateLimiter,
      now: this.now,
    });
  }

  recordResult(summary: ToolResultSummary): void {
    this.recentResults.push(summary);
    if (this.recentResults.length > MAX_RECENT_RESULTS) this.recentResults.shift();
  }

  recordCheck(check: { id: string; categories: readonly OwaspCategory[] }): void {
    this.executedChecks.add(check.id);
    for (const category of check.categories) this.executedCategories.add(category);
  }

  /** Add findings up to the per-category cap; returns the findings accepted. */
  addFindings(candidates: readonly Finding[]): Finding[] {
    const added: Finding[] = [];
    for (const finding of candidates) {
      if (!this.budget.recordFinding(finding.category)) continue;
      this.findings.push(finding);
      added.push(finding);
    }
    return added;
  }

  stop(reason: StopReason): void {
    if (this.stopReason !== undefined) return;
    this.stopReason = reason;
    this.budget.stop(reason);
  }
}
