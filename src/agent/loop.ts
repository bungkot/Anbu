import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { config } from "../config.js";
import { AuditLog } from "../audit/log.js";
import { RateLimiter } from "../guardrails/rate-limit.js";
import type { BudgetStatus, CoverageEntry, Report } from "../model/report.js";
import type { Finding } from "../model/finding.js";
import type { OwaspCategory, Scope } from "../model/scope.js";
import { OWASP_CATEGORIES } from "../model/scope.js";
import { intake } from "../intake.js";
import { defaultStartUrls, runRecon } from "../recon.js";
import type { AttackSurfaceSummary } from "../recon.js";
import { EvidenceStore } from "../store/evidence-store.js";
import { GuardedHttpClient } from "../tools/http.js";
import type { HttpRequestInput } from "../tools/http.js";
import { CHECKS, getCheck } from "../tools/checks/index.js";
import type { Check, CheckInput, CheckResult } from "../tools/checks/types.js";
import { createCheckContext } from "../tools/checks/context.js";
import type { ApprovalProvider } from "./approval.js";
import { denyAllApprovals } from "./approval.js";
import { RunContext } from "./context.js";
import { resolveBudgetLimits } from "./budget.js";
import type { StopReason } from "./budget.js";
import { OpenCodePlannerTransport, Planner } from "./planner.js";
import type { PlannerAction, PlannerTransport } from "./planner.js";
import { buildSystemPrompt, buildUserPrompt } from "./prompts.js";

export interface PentestOptions {
  scopePath: string;
  runId?: string;
  evidenceDir?: string;
  now?: () => Date;
  env?: (name: string) => string | undefined;
  fetchFn?: typeof fetch;
  /** Inject a fake transport in tests; omit to use the OpenCode/Ollama transport. */
  transport?: PlannerTransport;
  modelEnabled?: boolean;
  maxDepth?: number;
  maxUrls?: number;
  maxActionsPerPlan?: number;
  maxInputsPerCheck?: number;
  guardrailStreakLimit?: number;
  toolFailureStreakLimit?: number;
  /** Backoff after a rate-limit denial. Default 250ms; set 0 to disable. */
  throttleDelayMs?: number;
  approval?: ApprovalProvider;
}

export interface PentestRunResult {
  ok: boolean;
  errors?: string[];
  runId: string;
  scopeName: string;
  stopReason: StopReason;
  modelAvailable: boolean;
  findings: Finding[];
  coverage: CoverageEntry[];
  budgets: BudgetStatus;
  report: Report;
  summary?: AttackSurfaceSummary;
}

type ActionStatus = "ok" | "blocked" | "throttled" | "failed" | "skipped" | "halt";

interface StreakLimits {
  guardrail: number;
  tool: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Guardrail denials are not tool failures. Rate limiting is transient, a
 * per-check budget is a skip, and only scope/deny/authorization/policy
 * violations count as guardrail blocks.
 */
function classifyGuardrailMessage(message: string | undefined): ActionStatus {
  const lower = (message ?? "").toLowerCase();
  if (lower.includes("rate limit")) return "throttled";
  if (lower.includes("budget exhausted")) return "skipped";
  if (
    lower.includes("blocked by guardrails") ||
    lower.includes("requires human approval") ||
    lower.includes("out of scope") ||
    lower.includes("not covered") ||
    lower.includes("deny") ||
    lower.includes("not allowed") ||
    lower.includes("expired") ||
    lower.includes("read-only") ||
    lower.includes("exceeds policy")
  ) {
    return "blocked";
  }
  return "failed";
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function safeTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

function configBudgetStatus(): BudgetStatus {
  return {
    maxRequests: config.maxRequests,
    usedRequests: 0,
    maxDurationMinutes: config.maxDurationMinutes,
    elapsedMinutes: 0,
    maxModelTurns: config.maxModelTurns,
    usedModelTurns: 0,
  };
}

function failureResult(errors: string[]): PentestRunResult {
  const budgets = configBudgetStatus();
  const report: Report = {
    runId: "(not started)",
    scopeReference: "(unknown)",
    generatedAt: new Date().toISOString(),
    findings: [],
    coverage: [],
    budgets,
    stopReason: "human_stop",
  };
  return {
    ok: false,
    errors,
    runId: "(not started)",
    scopeName: "(unknown)",
    stopReason: "human_stop",
    modelAvailable: false,
    findings: [],
    coverage: [],
    budgets,
    report,
  };
}

function minimalAttackSurface(scope: Scope, maxDepth: number, maxUrls: number): AttackSurfaceSummary {
  const startUrls = defaultStartUrls(scope);
  return {
    targets: startUrls,
    startUrls,
    urls: [],
    forms: [],
    assets: [],
    technologies: [],
    blocked: [],
    requests: 0,
    truncated: false,
    maxDepth,
    maxUrls,
  };
}

function candidateUrls(summary: AttackSurfaceSummary): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();
  for (const url of [...summary.urls, ...summary.forms.map((form) => form.action)]) {
    if (seen.has(url)) continue;
    seen.add(url);
    urls.push(url);
    if (urls.length >= 20) break;
  }
  return urls;
}

function parameterNames(url: string, summary: AttackSurfaceSummary): string[] {
  const params: string[] = [];
  try {
    for (const key of new URL(url).searchParams.keys()) params.push(key);
  } catch {
    // Not a parseable URL; fall through to form parameters.
  }
  if (params.length === 0) {
    const form = summary.forms.find((candidate) => candidate.action === url);
    if (form !== undefined) params.push(...form.parameters);
  }
  return params.slice(0, 2);
}

function deriveCheckInputs(summary: AttackSurfaceSummary, maxInputs: number): CheckInput[] {
  const inputs: CheckInput[] = [];
  for (const url of candidateUrls(summary)) {
    if (inputs.length >= maxInputs) break;
    const params = parameterNames(url, summary);
    inputs.push(params.length > 0 ? { url, parameter: params[0] } : { url });
  }
  return inputs;
}

async function executeCheck(
  ctx: RunContext,
  check: Check,
  input: CheckInput,
  approval: ApprovalProvider,
): Promise<ActionStatus> {
  if (check.metadata.requiresApproval) {
    const approved = await approval.approve({
      action: `run_check:${check.metadata.id}`,
      method: input.method ?? "GET",
      url: input.url,
      reason: "check is state-changing and requires approval",
    });
    await ctx.audit.append(approved ? "approval.granted" : "approval.denied", {
      check: check.metadata.id,
      target: safeTarget(input.url),
    });
    if (!approved) {
      ctx.recordResult({
        tool: check.metadata.toolName,
        ok: false,
        url: input.url,
        error: "approval denied",
      });
      return "skipped";
    }
  }

  const checkCtx = createCheckContext({
    scope: ctx.scope,
    client: ctx.client,
    store: ctx.store,
    audit: ctx.audit,
    now: ctx.now,
    maxRequests: check.metadata.maxRequests,
  });

  const result: CheckResult = await check.run(checkCtx, input);
  ctx.recordCheck(check.metadata);

  const added = ctx.addFindings(result.findings);
  for (const finding of added) {
    await ctx.audit.append("finding", {
      check: check.metadata.id,
      category: finding.category,
      target: safeTarget(finding.affected.url),
      evidenceId: finding.evidence[0]?.evidenceId,
    });
  }
  await ctx.audit.append("check", {
    check: check.metadata.id,
    findings: result.findings.length,
    requests: result.requests,
  });
  ctx.recordResult({
    tool: check.metadata.toolName,
    ok: result.ok,
    url: input.url,
    error: result.error,
    detail: result.skipped,
  });

  if (result.ok) return "ok";
  return classifyGuardrailMessage(result.error);
}

async function executeObservation(ctx: RunContext, input: HttpRequestInput): Promise<ActionStatus> {
  const outcome = await ctx.client.request(input);
  let evidenceId: string | undefined;
  if (outcome.ok && outcome.response !== undefined) {
    const captured = await ctx.store.capture({
      request: {
        method: outcome.method,
        url: input.url,
        headers: input.headers,
        body: typeof input.body === "string" ? input.body : undefined,
      },
      response: {
        status: outcome.response.status,
        statusText: outcome.response.statusText,
        headers: outcome.response.headers,
        body: outcome.response.bodyText,
        bodyBytes: outcome.response.bodyBytes,
        truncated: outcome.response.truncated,
        durationMs: outcome.response.durationMs,
      },
    });
    if (captured.ok) evidenceId = captured.evidenceId;
  }

  await ctx.audit.append("observe", {
    method: outcome.method,
    target: safeTarget(input.url),
    status: outcome.response?.status,
    evidenceId,
  });
  ctx.recordResult({
    tool: "http_request",
    ok: outcome.ok,
    url: input.url,
    status: outcome.response?.status,
    evidenceId,
    error: outcome.error,
  });

  if (outcome.ok) return "ok";
  if (outcome.requiresApproval) return "blocked";
  return classifyGuardrailMessage(outcome.error);
}

async function executePlannerAction(
  ctx: RunContext,
  action: PlannerAction,
  approval: ApprovalProvider,
): Promise<ActionStatus> {
  switch (action.kind) {
    case "halt":
      await ctx.audit.append("planner.halt", { reason: action.reason });
      ctx.stop("planner_halt");
      return "halt";
    case "run_check": {
      const check = getCheck(action.checkId);
      if (check === undefined) {
        await ctx.audit.append("planner.unknown_check", { check: action.checkId });
        return "skipped";
      }
      return executeCheck(ctx, check, action.input, approval);
    }
    case "http_request":
      return executeObservation(ctx, action.input);
  }
}

function applyStatus(
  ctx: RunContext,
  status: ActionStatus,
  guardrail: number,
  tool: number,
  limits: StreakLimits,
): { guardrail: number; tool: number } {
  const nextGuardrail = status === "blocked" ? guardrail + 1 : 0;
  const nextTool = status === "failed" ? tool + 1 : 0;
  if (nextGuardrail >= limits.guardrail) ctx.stop("guardrail_streak");
  else if (nextTool >= limits.tool) ctx.stop("tool_failure_streak");
  return { guardrail: nextGuardrail, tool: nextTool };
}

function buildCoverage(ctx: RunContext, scope: Scope): CoverageEntry[] {
  return OWASP_CATEGORIES.map((category: OwaspCategory) => {
    if (!scope.testClasses.includes(category)) {
      return { category, status: "not_applicable", findings: 0 };
    }
    const findings = ctx.findings.filter((finding) => finding.category === category).length;
    if (ctx.executedCategories.has(category)) {
      return { category, status: "covered", findings };
    }
    return { category, status: "not_run", findings };
  });
}

/**
 * Run one authorized pentest: intake, recon, deterministic baseline, bounded
 * planner loop, then a report. The loop only starts with a valid scope and
 * stops on budget exhaustion, guardrail/tool streaks, or a planner halt.
 */
export async function runPentest(options: PentestOptions): Promise<PentestRunResult> {
  const now = options.now ?? (() => new Date());
  const env = options.env ?? ((name: string) => process.env[name]);
  const approval = options.approval ?? denyAllApprovals;
  const streakLimits: StreakLimits = {
    guardrail: options.guardrailStreakLimit ?? 5,
    tool: options.toolFailureStreakLimit ?? 5,
  };
  const throttleDelayMs = options.throttleDelayMs ?? 250;

  const intakeResult = await intake(options.scopePath, now(), env);
  if (!intakeResult.ok) return failureResult(intakeResult.errors);

  const scope = intakeResult.scope;
  const runId = options.runId ?? randomUUID();
  const evidenceRoot = join(options.evidenceDir ?? config.evidenceDir, runId);
  const audit = new AuditLog(join(evidenceRoot, "audit.log"), runId);
  const store = new EvidenceStore({ rootDir: evidenceRoot, now });
  const limits = resolveBudgetLimits(scope);
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost:
      scope.policy?.requestsPerSecondPerHost ?? config.requestsPerSecondPerHost,
    maxRequests: limits.maxRequests,
  });
  const client = new GuardedHttpClient({
    scope,
    rateLimiter,
    audit,
    now,
    env,
    fetchFn: options.fetchFn,
    maxResponseBodyBytes: limits.maxBodyBytes,
  });

  let transport = options.transport;
  let ownsTransport = false;
  if (transport === undefined && options.modelEnabled !== false) {
    transport = new OpenCodePlannerTransport();
    ownsTransport = true;
  }
  let modelAvailable = false;
  if (transport !== undefined) {
    try {
      await transport.start();
      modelAvailable = true;
    } catch (err) {
      await audit.append("planner.unavailable", { reason: errorMessage(err) });
    }
  }

  const maxDepth = options.maxDepth ?? 2;
  const maxUrls = options.maxUrls ?? 50;
  const recon = await runRecon({
    scope,
    rateLimiter,
    audit,
    fetchFn: options.fetchFn,
    env,
    maxDepth,
    maxUrls,
    maxResponseBodyBytes: limits.maxBodyBytes,
  });
  const attackSurface = recon.summary ?? minimalAttackSurface(scope, maxDepth, maxUrls);
  if (recon.summary === undefined) {
    await audit.append("recon.failed", { reason: recon.error ?? "unknown error" });
  }

  const ctx = new RunContext({
    runId,
    scope,
    limits,
    rateLimiter,
    audit,
    store,
    client,
    attackSurface,
    now,
    objective: "Identify and validate security findings within the authorized scope.",
  });
  ctx.modelAvailable = modelAvailable;
  await audit.append("run.start", {
    scope: scope.name,
    authorization: scope.authorization.reference,
    targets: scope.targets.map((target) => target.host),
  });

  let guardrailStreak = 0;
  let toolFailureStreak = 0;

  // Deterministic baseline first: cheap, high-signal, independent of the model.
  const baselineChecks = CHECKS.filter(
    (check) =>
      check.metadata.readOnly &&
      check.metadata.categories.some((category) => scope.testClasses.includes(category)),
  );
  for (const check of baselineChecks) {
    if (ctx.stopReason !== undefined) break;
    if (ctx.budget.exhaustedReason() !== undefined) {
      ctx.stop("budget_exhausted");
      break;
    }
    const inputs = deriveCheckInputs(attackSurface, options.maxInputsPerCheck ?? 2);
    for (const input of inputs) {
      if (ctx.stopReason !== undefined) break;
      if (ctx.budget.exhaustedReason() !== undefined) {
        ctx.stop("budget_exhausted");
        break;
      }
      const status = await executeCheck(ctx, check, input, approval);
      const streaks = applyStatus(ctx, status, guardrailStreak, toolFailureStreak, streakLimits);
      guardrailStreak = streaks.guardrail;
      toolFailureStreak = streaks.tool;
      if (status === "throttled" && throttleDelayMs > 0) await sleep(throttleDelayMs);
    }
  }

  // Planner loop: model-guided checks and observations using the remaining budget.
  if (transport !== undefined && modelAvailable && ctx.stopReason === undefined) {
    const planner = new Planner({
      transport,
      maxActionsPerPlan: options.maxActionsPerPlan ?? 10,
      allowedCategories: new Set(scope.testClasses),
    });
    let plannerFailures = 0;
    let emptyPlans = 0;

    while (ctx.stopReason === undefined) {
      const exhausted = ctx.budget.exhaustedReason();
      if (exhausted !== undefined) {
        ctx.stop(exhausted);
        break;
      }
      ctx.budget.recordModelTurn();
      const plan = await planner.plan(buildSystemPrompt(), buildUserPrompt(ctx));
      if (!plan.ok) {
        plannerFailures += 1;
        await audit.append("planner.error", { reason: plan.error });
        if (plannerFailures >= 2) {
          ctx.modelAvailable = false;
          await audit.append("planner.disabled", { reason: "repeated planner failures" });
          break;
        }
        continue;
      }
      plannerFailures = 0;
      if (plan.plan.actions.length === 0) {
        emptyPlans += 1;
        if (emptyPlans >= 2) break;
        continue;
      }
      emptyPlans = 0;

      for (const action of plan.plan.actions) {
        if (ctx.stopReason !== undefined) break;
        const actionBudget = ctx.budget.exhaustedReason();
        if (actionBudget !== undefined) {
          ctx.stop(actionBudget);
          break;
        }
        const status = await executePlannerAction(ctx, action, approval);
        const streaks = applyStatus(ctx, status, guardrailStreak, toolFailureStreak, streakLimits);
        guardrailStreak = streaks.guardrail;
        toolFailureStreak = streaks.tool;
        if (status === "throttled" && throttleDelayMs > 0) await sleep(throttleDelayMs);
      }
    }
  }

  if (ctx.stopReason === undefined) ctx.stop("completed");
  const stopReason: StopReason = ctx.stopReason ?? "completed";

  const budgets = ctx.budget.status();
  const coverage = buildCoverage(ctx, scope);
  const report: Report = {
    runId,
    scopeReference: scope.authorization.reference,
    generatedAt: now().toISOString(),
    findings: ctx.findings,
    coverage,
    budgets,
    stopReason,
  };
  await audit.append("run.end", {
    stopReason,
    findings: ctx.findings.length,
  });

  if (ownsTransport && transport !== undefined) {
    await transport.stop().catch(() => undefined);
  }

  return {
    ok: true,
    runId,
    scopeName: scope.name,
    stopReason,
    modelAvailable: ctx.modelAvailable,
    findings: ctx.findings,
    coverage,
    budgets,
    report,
    summary: attackSurface,
  };
}
