import { test } from "node:test";
import assert from "node:assert/strict";
import { dependenciesCheck } from "../../../src/tools/checks/dependencies.js";
import { securityHeadersCheck } from "../../../src/tools/checks/security-headers.js";
import { sqliCheck } from "../../../src/tools/checks/sqli.js";
import { makeScope } from "../helpers.js";
import { makeCheckContext } from "./helpers.js";

test("security-headers run captures evidence and returns findings", async () => {
  const fetchFn: typeof fetch = async () =>
    new Response("<html></html>", { status: 200, headers: {} });
  const { ctx } = await makeCheckContext({ fetchFn, maxRequests: 5 });

  const result = await securityHeadersCheck.run(ctx, { url: "https://example.test/" });
  assert.equal(result.ok, true);
  assert.ok(result.findings.length > 0);
  assert.ok(result.evidence.length >= 1);
  assert.equal(result.requests, 1);
});

test("sqli run issues bounded probes and captures the triggering evidence", async () => {
  const fetchFn: typeof fetch = async (input) => {
    const url = String(input);
    if (url.includes("%27") || url.includes("'")) {
      return new Response("You have an error in your SQL syntax", { status: 500 });
    }
    return new Response("Welcome", { status: 200 });
  };
  const { ctx } = await makeCheckContext({ fetchFn, maxRequests: 20 });

  const result = await sqliCheck.run(ctx, {
    url: "https://example.test/search?q=1",
    parameter: "q",
  });
  assert.equal(result.ok, true);
  assert.ok(result.findings.length > 0);
  assert.ok(result.requests <= sqliCheck.metadata.maxRequests);
  assert.ok(result.evidence.length >= 2);
});

test("sqli run stops at the context request budget", async () => {
  const fetchFn: typeof fetch = async () => new Response("Welcome", { status: 200 });
  const { ctx } = await makeCheckContext({ fetchFn, maxRequests: 2 });

  const result = await sqliCheck.run(ctx, {
    url: "https://example.test/search?q=1",
    parameter: "q",
  });
  assert.equal(result.ok, true);
  assert.ok(result.requests <= 2);
});

test("a check returns an error when the request is blocked by scope", async () => {
  const scope = makeScope({
    targets: [{ host: "example.test", scheme: "https", port: 443, paths: ["/"] }],
  });
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const { ctx } = await makeCheckContext({ scope, fetchFn, maxRequests: 5 });

  const result = await securityHeadersCheck.run(ctx, { url: "https://evil.test/" });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /scope/);
  assert.equal(calls, 0);
});

test("dependencies run analyzes supplied dependencies without network access", async () => {
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const { ctx } = await makeCheckContext({ fetchFn, maxRequests: 5 });

  const result = await dependenciesCheck.run(ctx, {
    url: "https://example.test/",
    options: { dependencies: [{ name: "lodash", version: "4.17.20" }] },
  });
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.requests, 0);
  assert.equal(calls, 0);
});
