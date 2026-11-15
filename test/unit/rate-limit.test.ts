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

test("acquire waits for a per-host token instead of denying", async () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 2, maxRequests: 100 });
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);
  assert.equal(limiter.tryAcquire("a.test", 0).allowed, true);

  const sleeps: number[] = [];
  const decision = await limiter.acquire("a.test", 0, {
    maxWaitMs: 1000,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  assert.equal(decision.allowed, true);
  assert.deepEqual(sleeps, [500]);
});

test("acquire denies when waiting would exceed the configured limit", async () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 2, maxRequests: 100 });
  limiter.tryAcquire("a.test", 0);
  limiter.tryAcquire("a.test", 0);

  let slept = false;
  const decision = await limiter.acquire("a.test", 0, {
    maxWaitMs: 499,
    sleep: async () => {
      slept = true;
    },
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason ?? "", /per-host/);
  assert.equal(slept, false);
});

test("acquire with a zero wait limit denies immediately", async () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 2, maxRequests: 100 });
  limiter.tryAcquire("a.test", 0);
  limiter.tryAcquire("a.test", 0);

  let slept = false;
  const decision = await limiter.acquire("a.test", 0, {
    maxWaitMs: 0,
    sleep: async () => {
      slept = true;
    },
  });
  assert.equal(decision.allowed, false);
  assert.equal(slept, false);
});

test("acquire never waits out the global budget", async () => {
  const limiter = new RateLimiter({ requestsPerSecondPerHost: 100, maxRequests: 1 });
  limiter.tryAcquire("a.test", 0);

  let slept = false;
  const decision = await limiter.acquire("b.test", 0, {
    maxWaitMs: 1000,
    sleep: async () => {
      slept = true;
    },
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason ?? "", /global/);
  assert.equal(slept, false);
});
