import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, isStateChangingMethod } from "../../src/guardrails/policy.js";
import { makeScope } from "./helpers.js";

test("state-changing method detection", () => {
  assert.equal(isStateChangingMethod("POST"), true);
  assert.equal(isStateChangingMethod("get"), false);
  assert.equal(isStateChangingMethod("DELETE"), true);
});

test("read-only scope blocks POST", () => {
  const decision = evaluatePolicy(makeScope({ readOnly: true }), {
    method: "POST",
    url: "https://example.test/api",
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason, /read-only/);
});

test("state-changing defaults to deny", () => {
  const decision = evaluatePolicy(makeScope(), {
    method: "POST",
    url: "https://example.test/api",
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason, /denied/);
});

test("approve mode requires approval", () => {
  const decision = evaluatePolicy(makeScope({ stateChanging: { mode: "approve" } }), {
    method: "POST",
    url: "https://example.test/api",
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.requiresApproval, true);
});

test("allow mode permits only listed endpoints", () => {
  const scope = makeScope({
    stateChanging: { mode: "allow", allow: ["POST /api/contact"] },
  });
  assert.equal(
    evaluatePolicy(scope, { method: "POST", url: "https://example.test/api/contact" }).allowed,
    true,
  );
  assert.equal(
    evaluatePolicy(scope, { method: "POST", url: "https://example.test/api/other" }).allowed,
    false,
  );
});

test("body size is enforced", () => {
  const scope = makeScope({ policy: { maxBodyBytes: 8 } });
  const decision = evaluatePolicy(scope, {
    method: "POST",
    url: "https://example.test/api",
    body: "123456789",
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason, /maxBodyBytes/);
});
