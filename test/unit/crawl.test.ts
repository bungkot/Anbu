import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/audit/log.js";
import { RateLimiter } from "../../src/guardrails/rate-limit.js";
import { GuardedHttpClient } from "../../src/tools/http.js";
import { Crawler } from "../../src/tools/crawl.js";
import type { Scope } from "../../src/model/scope.js";
import { makeScope } from "./helpers.js";

type Routes = Record<string, () => Response>;

function html(body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
  });
}

function makeSite(routes: Routes): { fetchFn: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    const handler = routes[url];
    if (handler === undefined) {
      return new Response("not found", {
        status: 404,
        headers: { "content-type": "text/plain" },
      });
    }
    return handler();
  };
  return { fetchFn, calls };
}

async function makeCrawler(options?: {
  scope?: Scope;
  fetchFn?: typeof fetch;
  maxRequests?: number;
}) {
  const scope = options?.scope ?? makeScope();
  const dir = await mkdtemp(join(tmpdir(), "anbu-crawl-"));
  const audit = new AuditLog(join(dir, "audit.log"), "run-test");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: 1000,
    maxRequests: options?.maxRequests ?? 1000,
  });
  const client = new GuardedHttpClient({
    scope,
    rateLimiter,
    audit,
    fetchFn: options?.fetchFn,
    env: () => "test-token",
  });
  return { crawler: new Crawler({ client, scope }), audit, scope };
}

const START = "https://example.test/";

test("crawls in-scope pages and extracts forms, assets, and technologies", async () => {
  const startHtml = `<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.5">
<link rel="stylesheet" href="/assets/site.css">
<script src="/assets/react.min.js"></script>
</head><body>
<a href="/a">A</a>
<a href="/b">B</a>
<a href="https://evil.test/outside">outside</a>
<a href="#top">top</a>
<a href="mailto:user@example.test">mail</a>
<form action="/login" method="post">
  <input name="username">
  <input name="password" type="password">
  <button name="submit">Go</button>
</form>
<img src="/assets/logo.png">
</body></html>`;

  const site = makeSite({
    [START]: () => html(startHtml, { server: "nginx/1.25" }),
    "https://example.test/a": () => html('<a href="/c">C</a>'),
    "https://example.test/b": () =>
      new Response("plain", { status: 200, headers: { "content-type": "text/plain" } }),
    "https://example.test/c": () => html("<p>done</p>"),
  });

  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({
    startUrl: START,
    maxDepth: 2,
    maxUrls: 20,
  });

  assert.equal(result.ok, true, result.error);
  assert.deepEqual(result.urls, [
    START,
    "https://example.test/a",
    "https://example.test/b",
    "https://example.test/c",
  ]);
  assert.equal(result.requests, 4);
  assert.equal(result.truncated, false);
  assert.deepEqual(result.blocked, []);
  assert.equal(site.calls.includes("https://evil.test/outside"), false);
  assert.equal(result.maxDepth, 2);
  assert.equal(result.maxUrls, 20);

  assert.deepEqual(result.forms, [
    {
      pageUrl: START,
      action: "https://example.test/login",
      method: "POST",
      parameters: ["username", "password", "submit"],
    },
  ]);

  const assets = result.assets.map((asset) => `${asset.type} ${asset.url}`).sort();
  assert.deepEqual(assets, [
    "image https://example.test/assets/logo.png",
    "script https://example.test/assets/react.min.js",
    "stylesheet https://example.test/assets/site.css",
  ]);

  const technologies = result.technologies.map((marker) => marker.name);
  assert.ok(technologies.includes("generator"));
  assert.ok(technologies.includes("react"));
  assert.ok(technologies.includes("server"));
});

test("does not follow links beyond maxDepth", async () => {
  const site = makeSite({
    [START]: () => html('<a href="/a">A</a>'),
    "https://example.test/a": () => html('<a href="/b">B</a>'),
    "https://example.test/b": () => html('<a href="/c">C</a>'),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 1 });
  assert.deepEqual(result.urls, [START, "https://example.test/a"]);
  assert.equal(result.truncated, false);
});

test("visits only the start URL at maxDepth 0", async () => {
  const site = makeSite({
    [START]: () => html('<a href="/a">A</a>'),
    "https://example.test/a": () => html("A"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 0 });
  assert.deepEqual(result.urls, [START]);
  assert.equal(result.requests, 1);
});

test("stops at maxUrls and reports truncation", async () => {
  const site = makeSite({
    [START]: () => html('<a href="/a">A</a><a href="/b">B</a><a href="/c">C</a>'),
    "https://example.test/a": () => html("A"),
    "https://example.test/b": () => html("B"),
    "https://example.test/c": () => html("C"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 2, maxUrls: 2 });
  assert.equal(result.urls.length, 2);
  assert.equal(result.requests, 2);
  assert.equal(result.truncated, true);
});

test("stops crawling when the global request budget is exhausted", async () => {
  const site = makeSite({
    [START]: () => html('<a href="/a">A</a>'),
    "https://example.test/a": () => html('<a href="/b">B</a>'),
    "https://example.test/b": () => html('<a href="/c">C</a>'),
    "https://example.test/c": () => html("C"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn, maxRequests: 2 });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 3, maxUrls: 10 });

  assert.equal(result.ok, true, result.error);
  assert.equal(result.requests, 3);
  assert.equal(result.truncated, true);
  assert.equal(result.blocked.length, 1);
  assert.equal(result.blocked[0].url, "https://example.test/b");
  assert.match(result.blocked[0].reason, /budget/i);
});

test("refuses an invalid start URL before fetching", async () => {
  const site = makeSite({});
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: "not a url" });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /invalid/);
  assert.equal(result.requests, 0);
  assert.equal(site.calls.length, 0);
});

test("refuses an out-of-scope start URL before fetching", async () => {
  const site = makeSite({});
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: "https://evil.test/" });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /scope/i);
  assert.equal(result.requests, 0);
  assert.equal(site.calls.length, 0);
});

test("skips denied and out-of-scope links while staying in scope", async () => {
  const scope = makeScope({
    deny: [{ host: "example.test", paths: ["/admin"] }],
  });
  const site = makeSite({
    [START]: () =>
      html('<a href="/admin">admin</a><a href="/ok">ok</a><a href="https://evil.test/">evil</a>'),
    "https://example.test/ok": () => html("ok"),
  });
  const { crawler } = await makeCrawler({ scope, fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 1 });

  assert.deepEqual(result.urls, [START, "https://example.test/ok"]);
  assert.deepEqual(result.blocked, []);
  assert.equal(site.calls.includes("https://example.test/admin"), false);
  assert.equal(site.calls.includes("https://evil.test/"), false);
});

test("records guard-blocked links when stayInScope is false", async () => {
  const scope = makeScope({
    deny: [{ host: "example.test", paths: ["/admin"] }],
  });
  const site = makeSite({
    [START]: () => html('<a href="/admin">admin</a><a href="/ok">ok</a>'),
    "https://example.test/ok": () => html("ok"),
  });
  const { crawler } = await makeCrawler({ scope, fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 1, stayInScope: false });

  assert.equal(result.blocked.length, 1);
  assert.equal(result.blocked[0].url, "https://example.test/admin");
  assert.match(result.blocked[0].reason, /deny/i);
  assert.equal(site.calls.includes("https://example.test/admin"), false);
});

test("records an out-of-scope link as blocked when stayInScope is false", async () => {
  const site = makeSite({
    [START]: () => html('<a href="https://evil.test/">evil</a>'),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 1, stayInScope: false });

  assert.equal(result.blocked.length, 1);
  assert.equal(result.blocked[0].url, "https://evil.test/");
  assert.match(result.blocked[0].reason, /scope/i);
  assert.equal(site.calls.length, 1);
});

test("does not parse links out of non-HTML responses", async () => {
  const site = makeSite({
    [START]: () => html('<a href="/page">page</a>'),
    "https://example.test/page": () =>
      new Response('<a href="/hidden">hidden</a>', {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    "https://example.test/hidden": () => html("hidden"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 2 });

  assert.deepEqual(result.urls, [START, "https://example.test/page"]);
  assert.equal(site.calls.includes("https://example.test/hidden"), false);
});

test("deduplicates URLs and drops fragments", async () => {
  const site = makeSite({
    [START]: () =>
      html('<a href="/a">A</a><a href="/a#section">A again</a><a href="/a?x=1">query</a>'),
    "https://example.test/a": () => html("A"),
    "https://example.test/a?x=1": () => html("A query"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START, maxDepth: 1 });

  assert.deepEqual(result.urls, [START, "https://example.test/a", "https://example.test/a?x=1"]);
});

test("resolves relative links against a base href", async () => {
  const site = makeSite({
    "https://example.test/dir/page": () => html('<base href="/sub/"><a href="child">Child</a>'),
    "https://example.test/sub/child": () => html("child"),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({
    startUrl: "https://example.test/dir/page",
    maxDepth: 1,
  });

  assert.deepEqual(result.urls, [
    "https://example.test/dir/page",
    "https://example.test/sub/child",
  ]);
});

test("defaults a form action to the page URL and the method to GET", async () => {
  const site = makeSite({
    "https://example.test/search": () => html('<form><input name="q"><input name="page"></form>'),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: "https://example.test/search" });

  assert.deepEqual(result.forms, [
    {
      pageUrl: "https://example.test/search",
      action: "https://example.test/search",
      method: "GET",
      parameters: ["q", "page"],
    },
  ]);
});

test("deduplicates repeated assets and technology markers", async () => {
  const site = makeSite({
    [START]: () =>
      html(
        '<script src="/assets/react.min.js"></script><script src="/assets/react.min.js"></script>' +
          '<meta name="generator" content="WordPress"><meta name="generator" content="WordPress">',
      ),
  });
  const { crawler } = await makeCrawler({ fetchFn: site.fetchFn });
  const result = await crawler.crawl({ startUrl: START });

  assert.equal(result.assets.length, 1);
  assert.equal(result.technologies.filter((marker) => marker.name === "react").length, 1);
  assert.equal(result.technologies.filter((marker) => marker.name === "generator").length, 1);
});
