import { test } from "node:test";
import assert from "node:assert/strict";
import type { OwaspCategory } from "../../../src/model/scope.js";
import { Planner, parsePlannerResponse } from "../../../src/agent/planner.js";
import { FakePlannerTransport } from "./helpers.js";

const validPlan = {
  objective: "Find injection issues",
  actions: [
    {
      kind: "run_check",
      checkId: "sqli",
      input: { url: "https://example.test/search?q=1", parameter: "q" },
    },
    { kind: "http_request", input: { method: "GET", url: "https://example.test/" } },
    { kind: "halt", reason: "objective met" },
  ],
  rationale: "Cheap deterministic checks first.",
};

test("parses a fenced plan containing every closed action kind", () => {
  const text = `Here is the plan:\n\`\`\`json\n${JSON.stringify(validPlan)}\n\`\`\``;
  const result = parsePlannerResponse(text, { maxActions: 3 });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.plan.objective, validPlan.objective);
  assert.equal(result.plan.rationale, validPlan.rationale);
  assert.deepEqual(result.plan.actions, validPlan.actions);
});

test("rejects a response without a JSON object", () => {
  const result = parsePlannerResponse("I cannot help with that.", { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /did not contain a JSON object/);
});

test("rejects text without an embedded JSON object", () => {
  const result = parsePlannerResponse("[1, 2, 3]", { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /did not contain a JSON object/);
});

test("rejects malformed JSON", () => {
  const result = parsePlannerResponse("{not json}", { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /not valid JSON/);
});

test("rejects a plan without an actions array", () => {
  const result = parsePlannerResponse(JSON.stringify({ objective: "x" }), { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /actions array/);
});

test("rejects more actions than the plan budget allows", () => {
  const text = JSON.stringify({
    actions: [
      { kind: "http_request", input: { url: "https://example.test/1" } },
      { kind: "http_request", input: { url: "https://example.test/2" } },
    ],
  });
  const result = parsePlannerResponse(text, { maxActions: 1 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /exceeding the limit of 1/);
});

test("rejects an action kind outside the closed schema", () => {
  const text = JSON.stringify({
    actions: [{ kind: "drop_table", input: { url: "https://example.test/" } }],
  });
  const result = parsePlannerResponse(text, { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /unknown action kind/);
});

test("rejects an unknown check id", () => {
  const text = JSON.stringify({
    actions: [{ kind: "run_check", checkId: "not-a-check", input: { url: "https://example.test/" } }],
  });
  const result = parsePlannerResponse(text, { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /unknown check/);
});

test("rejects a run_check input without a URL", () => {
  const text = JSON.stringify({
    actions: [{ kind: "run_check", checkId: "sqli", input: { parameter: "q" } }],
  });
  const result = parsePlannerResponse(text, { maxActions: 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /url must be a non-empty string/);
});

test("rejects a check outside the in-scope test classes", () => {
  const allowed = new Set<OwaspCategory>(["A05"]);
  const text = JSON.stringify({
    actions: [
      { kind: "run_check", checkId: "security-headers", input: { url: "https://example.test/" } },
    ],
  });
  const result = parsePlannerResponse(text, { maxActions: 5, allowedCategories: allowed });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /outside the in-scope test classes/);
});

test("Planner.plan surfaces a transport failure as an error", async () => {
  const transport = new FakePlannerTransport();
  const planner = new Planner({ transport, maxActionsPerPlan: 5 });

  const result = await planner.plan("system prompt", "user prompt");

  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /no scripted response/);
});

test("Planner.plan sends the prompts through the transport and parses the reply", async () => {
  const transport = new FakePlannerTransport([
    JSON.stringify({ objective: "x", actions: [{ kind: "halt", reason: "done" }] }),
  ]);
  const planner = new Planner({ transport, maxActionsPerPlan: 5 });

  const result = await planner.plan("system prompt", "user prompt");

  assert.equal(result.ok, true);
  assert.deepEqual(transport.requests, [
    { system: "system prompt", user: "user prompt" },
  ]);
  if (result.ok) {
    assert.deepEqual(result.plan.actions, [{ kind: "halt", reason: "done" }]);
  }
});
