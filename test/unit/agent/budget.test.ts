import { test } from "node:test";
import assert from "node:assert/strict";
import { config } from "../../../src/config.js";
import type { OwaspCategory } from "../../../src/model/scope.js";
import { RateLimiter } from "../../../src/guardrails/rate-limit.js";
import type { BudgetLimits } from "../../../src/agent/budget.js";
import { resolveBudgetLimits, RunBudget } from "../../../src/agent/budget.js";
import { makeScope } from "../helpers.js";

function limits(overrides: Partial<BudgetLimits> = {}): BudgetLimits {
  return {
    maxRequests: 100,
    maxDurationMinutes: 60,
    maxModelTurns: 10,
    maxFindingsPerCategory: 3,
    maxBodyBytes: 4096,
    maxRedirects: 2,
    ...overrides,
  };
}

function rateLimiter(maxRequests = 100): RateLimiter {
  return new RateLimiter({ requestsPerSecondPerHost: 1000, maxRequests });
}

test("resolveBudgetLimits falls back to config when the scope has no policy", () => {
  const resolved = resolveBudgetLimits(makeScope());
  assert.equal(resolved.maxRequests, config.maxRequests);
  assert.equal(resolved.maxDurationMinutes, config.maxDurationMinutes);
  assert.equal(resolved.maxModelTurns, config.maxModelTurns);
  assert.equal(resolved.maxFindingsPerCategory, config.maxFindingsPerCategory);
  assert.equal(resolved.maxBodyBytes, config.maxBodyBytes);
  assert.equal(resolved.maxRedirects, config.maxRedirects);
});

test("resolveBudgetLimits lets the scope policy override every default", () => {
  const scope = makeScope({
    policy: {
      maxRequests: 7,
      maxDurationMinutes: 8,
      maxModelTurns: 9,
      maxFindingsPerCategory: 4,
      maxBodyBytes: 500,
      maxRedirects: 1,
    },
  });
  const resolved = resolveBudgetLimits(scope);
  assert.deepEqual(resolved, {
    maxRequests: 7,
    maxDurationMinutes: 8,
    maxModelTurns: 9,
    maxFindingsPerCategory: 4,
    maxBodyBytes: 500,
    maxRedirects: 1,
  });
});

test("RunBudget stops when the global request budget is exhausted", () => {
  const limiter = rateLimiter(2);
  limiter.tryAcquire("example.test");
  limiter.tryAcquire("example.test");
  const budget = new RunBudget({ limits: limits({ maxRequests: 2 }), rateLimiter: limiter });

  assert.equal(budget.exhaustedReason(), "budget_exhausted");
  assert.equal(budget.remainingRequests, 0);
  assert.equal(budget.status().usedRequests, 2);
});

test("RunBudget stops when the model-turn budget is exhausted", () => {
  const budget = new RunBudget({
    limits: limits({ maxModelTurns: 2 }),
    rateLimiter: rateLimiter(),
  });

  assert.equal(budget.exhaustedReason(), undefined);
  budget.recordModelTurn();
  budget.recordModelTurn();

  assert.equal(budget.exhaustedReason(), "budget_exhausted");
  assert.equal(budget.remainingModelTurns, 0);
  assert.equal(budget.status().usedModelTurns, 2);
});

test("RunBudget tracks elapsed minutes against the injected clock", () => {
  let current = Date.parse("2026-06-01T00:00:00Z");
  const budget = new RunBudget({
    limits: limits({ maxDurationMinutes: 10 }),
    rateLimiter: rateLimiter(),
    now: () => new Date(current),
  });

  current += 5 * 60_000;
  assert.ok(Math.abs(budget.remainingMinutes - 5) < 0.001);
  assert.ok(Math.abs(budget.status().elapsedMinutes - 5) < 0.001);

  current += 6 * 60_000;
  assert.equal(budget.exhaustedReason(), "budget_exhausted");
});

test("RunBudget caps findings per OWASP category", () => {
  const budget = new RunBudget({
    limits: limits({ maxFindingsPerCategory: 2 }),
    rateLimiter: rateLimiter(),
  });
  const category: OwaspCategory = "A05";

  assert.equal(budget.recordFinding(category), true);
  assert.equal(budget.recordFinding(category), true);
  assert.equal(budget.recordFinding(category), false);
  assert.equal(budget.findingsCount(category), 2);
});

test("RunBudget keeps the first stop reason and reports it as the exhaustion cause", () => {
  const budget = new RunBudget({ limits: limits(), rateLimiter: rateLimiter() });

  budget.stop("planner_halt");
  budget.stop("completed");

  assert.equal(budget.stopReason, "planner_halt");
  assert.equal(budget.exhaustedReason(), "planner_halt");
});
