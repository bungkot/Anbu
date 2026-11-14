import { test } from "node:test";
import assert from "node:assert/strict";
import type { OwaspCategory } from "../../../src/model/scope.js";
import { sqliCheck, xssCheck } from "../../../src/tools/checks/index.js";
import { MAX_RECENT_RESULTS } from "../../../src/agent/context.js";
import { makeRunContext, makeTestFinding } from "./helpers.js";

test("RunContext.addFindings accepts findings up to the per-category cap", async () => {
  const { ctx } = await makeRunContext({ limits: { maxFindingsPerCategory: 2 } });

  const accepted = ctx.addFindings([
    makeTestFinding("first"),
    makeTestFinding("second"),
    makeTestFinding("third"),
  ]);

  assert.equal(accepted.length, 2);
  assert.equal(ctx.findings.length, 2);
  assert.deepEqual(
    ctx.findings.map((finding) => finding.title),
    ["first", "second"],
  );
});

test("RunContext keeps only the most recent tool results", async () => {
  const { ctx } = await makeRunContext();

  for (let i = 0; i < MAX_RECENT_RESULTS + 1; i++) {
    ctx.recordResult({ tool: `tool-${i}`, ok: true });
  }

  assert.equal(ctx.recentResults.length, MAX_RECENT_RESULTS);
  assert.equal(ctx.recentResults[0].tool, "tool-1");
});

test("RunContext.stop is sticky and stops the shared budget", async () => {
  const { ctx } = await makeRunContext();

  ctx.stop("planner_halt");
  ctx.stop("completed");

  assert.equal(ctx.stopReason, "planner_halt");
  assert.equal(ctx.budget.stopReason, "planner_halt");
});

test("RunContext.recordCheck tracks executed checks and categories", async () => {
  const { ctx } = await makeRunContext();

  ctx.recordCheck(sqliCheck.metadata);
  ctx.recordCheck(xssCheck.metadata);

  assert.ok(ctx.executedChecks.has("sqli"));
  assert.ok(ctx.executedChecks.has("xss"));
  const categories: OwaspCategory[] = ["A05"];
  for (const category of categories) {
    assert.ok(ctx.executedCategories.has(category));
  }
});
