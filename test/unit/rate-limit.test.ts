import { test } from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../../src/guardrails/rate-limit.js";

test("global budget is enforced", () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 100, maxRequests: 2 });
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  assert.equal(limiter.tryAcquire("b.test", 0).allowed, true);
  const denied = limiter.tryAcquire("c.test", 0);
  assert.equal(denied.allowed, false);
  if (!denied.allowed) assert.match(denied.reason ?? "", /global/);
  assert.equal(limiter.remainingGlobal, 0);
});

test("per-host burst is limited", () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 2, maxRequests: 100 });
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  const denied = limiter.tryAcquire("a.test", 0);
  assert.equal(denied.allowed, false);
  if (!denied.allowed) assert.match(denied.reason ?? "", /per-host/);
  assert.equal(limiter.tryAcquire("b.test", 0).allowed, true);
});

test("tokens refill over time", () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 2, maxRequests: 100 });
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, false);
  assert.equal(limiter.tryAcquire("a.test", 1000).allowed, true);
});
