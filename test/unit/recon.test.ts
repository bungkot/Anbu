import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/audit/log.js";
import { RateLimiter } from "../../src/guardrails/rate-limit.js";
import { runRecon } from "../../src/recon.js";
import type { Scope } from "../../src/model/scope.js";
import { makeScope } from "./helpers.js";

type Routes = Record<string, () => Response>;

function html(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function makeSite(routes: Routes): { fetchFn: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    const handler = routes[url];
    if (handler === undefined) {
      return new Response("not found", { status: 404 });
    }
    return handler();
  };
  return { fetchFn, calls };
}

async function makeRecon(options: {
  scope: Scope;
  fetchFn?: typeof fetch;
  startUrls?: string[];
  maxDepth?: number;
  maxUrls?: number;
  maxRequests?: number;
}) {
  const dir = await mkdtemp(join(tmpdir(), "anbu-recon-"));
  const audit = new AuditLog(join(dir, "audit.log"), "run-test");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: 1000,
    maxRequests: options.maxRequests ?? 1000,
  });
  const result = await runRecon({
    scope: options.scope,
    startUrls: options.startUrls,
    maxDepth: options.maxDepth,
    maxUrls: options.maxUrls,
    rateLimiter,
    audit,
    fetchFn: options.fetchFn,
    env: () => "test-token",
  });
  return { result, audit };
}

test("recon crawls every concrete target and aggregates the attack surface", async () => {
  const scope = makeScope({
    targets: [
      { host: "example.test", scheme: "https", port: 443, paths: ["/"] },
      { host: "api.test", scheme: "https", port: 443, paths: ["/"] },
    ],
  });
  const site = makeSite({
    "https://example.test/": () => html('<a href="/a">A</a><a href="https://evil.test/">evil</a>'),
    "https://example.test/a": () =>
      html('<form action="/login" method="post"><input name="u"></form>'),
    "https://api.test/": () => html('<meta name="generator" content="Express">'),
  });

  const { result } = await makeRecon({ scope, fetchFn: site.fetchFn });
  assert.equal(result.ok, true, result.error);
  const summary = result.summary;
  assert.ok(summary);

  assert.deepEqual(summary.startUrls, ["https://example.test/", "https://api.test/"]);
  assert.deepEqual(summary.targets, ["https://example.test", "https://api.test"]);
  assert.ok(summary.urls.includes("https://example.test/a"));
  assert.equal(summary.urls.includes("https://evil.test/"), false);
  assert.equal(site.calls.includes("https://evil.test/"), false);
  assert.equal(summary.requests, 3);
  assert.equal(summary.truncated, false);
  assert.equal(summary.forms.length, 1);
  assert.equal(summary.forms[0].action, "https://example.test/login");
  assert.ok(summary.technologies.some((marker) => marker.name === "generator"));
});

test("recon honors an explicit start URL", async () => {
  const scope = makeScope({
    targets: [{ host: "example.test", scheme: "https", port: 443, paths: ["/"] }],
  });
  const site = makeSite({
    "https://example.test/": () => html('<a href="/a">A</a>'),
    "https://example.test/a": () => html('<a href="/b">B</a>'),
    "https://example.test/b": () => html("B"),
  });

  const { result } = await makeRecon({
    scope,
    fetchFn: site.fetchFn,
    startUrls: ["https://example.test/a"],
    maxDepth: 1,
  });
  assert.equal(result.ok, true, result.error);
  const summary = result.summary;
  assert.ok(summary);
  assert.deepEqual(summary.startUrls, ["https://example.test/a"]);
  assert.deepEqual(summary.urls, ["https://example.test/a", "https://example.test/b"]);
});

test("recon derives the first allowed path prefix as the start URL", async () => {
  const scope = makeScope({
    targets: [{ host: "example.test", scheme: "https", port: 443, paths: ["/app", "/api"] }],
  });
  const site = makeSite({
    "https://example.test/app": () => html("app"),
  });

  const { result } = await makeRecon({ scope, fetchFn: site.fetchFn });
  assert.equal(result.ok, true, result.error);
  assert.ok(result.summary);
  assert.deepEqual(result.summary.startUrls, ["https://example.test/app"]);
});

test("recon shares the request budget across targets", async () => {
  const scope = makeScope({
    targets: [
      { host: "example.test", scheme: "https", port: 443, paths: ["/"] },
      { host: "api.test", scheme: "https", port: 443, paths: ["/"] },
    ],
  });
  const site = makeSite({
    "https://example.test/": () => html('<a href="/a">A</a>'),
    "https://example.test/a": () => html("A"),
    "https://api.test/": () => html("api"),
  });

  const { result } = await makeRecon({ scope, fetchFn: site.fetchFn, maxRequests: 2 });
  assert.equal(result.ok, true, result.error);
  const summary = result.summary;
  assert.ok(summary);
  assert.equal(summary.requests, 3);
  assert.equal(summary.truncated, true);
  assert.equal(summary.blocked.length, 1);
  assert.equal(summary.blocked[0].url, "https://api.test/");
  assert.match(summary.blocked[0].reason, /budget/i);
});

test("recon refuses a scope with no concrete target host", async () => {
  const scope = makeScope({
    targets: [{ host: "*.example.test", scheme: "https", port: 443, paths: ["/"] }],
  });
  const site = makeSite({});
  const { result } = await makeRecon({ scope, fetchFn: site.fetchFn });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /concrete/);
  assert.equal(result.crawls.length, 0);
  assert.equal(site.calls.length, 0);
});

test("recon refuses an out-of-scope explicit start URL before fetching", async () => {
  const scope = makeScope({
    targets: [{ host: "example.test", scheme: "https", port: 443, paths: ["/"] }],
  });
  const site = makeSite({});
  const { result } = await makeRecon({
    scope,
    fetchFn: site.fetchFn,
    startUrls: ["https://evil.test/"],
  });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /scope/i);
  assert.equal(site.calls.length, 0);
});
