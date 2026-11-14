import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/audit/log.js";
import { RateLimiter } from "../../src/guardrails/rate-limit.js";
import { GuardedHttpClient } from "../../src/tools/http.js";
import { makeScope } from "./helpers.js";

type Scope = ReturnType<typeof makeScope>;

async function makeClient(options?: {
  scope?: Scope;
  fetchFn?: typeof fetch;
  maxResponseBodyBytes?: number;
  env?: (name: string) => string | undefined;
}) {
  const dir = await mkdtemp(join(tmpdir(), "anbu-http-"));
  const audit = new AuditLog(join(dir, "audit.log"), "run-test");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: 100,
    maxRequests: 1000,
  });
  const client = new GuardedHttpClient({
    scope: options?.scope ?? makeScope(),
    rateLimiter,
    audit,
    fetchFn: options?.fetchFn,
    maxResponseBodyBytes: options?.maxResponseBodyBytes,
    env: options?.env ?? (() => "test-token"),
  });
  return { client, audit };
}

test("blocks an out-of-scope request before fetching", async () => {
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const { client } = await makeClient({ fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://evil.test/" });
  assert.equal(outcome.ok, false);
  assert.match(outcome.error ?? "", /scope/);
  assert.equal(calls, 0);
});

test("blocks a denied path before fetching", async () => {
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const scope = makeScope({ deny: [{ host: "example.test", paths: ["/admin/delete"] }] });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/admin/delete" });
  assert.equal(outcome.ok, false);
  assert.match(outcome.error ?? "", /deny/);
  assert.equal(calls, 0);
});

test("sends an allowed request and returns the response", async () => {
  const fetchFn: typeof fetch = async () => new Response("hello", { status: 200 });
  const { client } = await makeClient({ fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/" });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.response?.status, 200);
  assert.equal(outcome.response?.bodyText, "hello");
});

test("blocks a body larger than the policy maximum before fetching", async () => {
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const scope = makeScope({ policy: { maxBodyBytes: 10 } });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({
    method: "POST",
    url: "https://example.test/",
    body: "x".repeat(20),
  });
  assert.equal(outcome.ok, false);
  assert.match(outcome.error ?? "", /body/);
  assert.equal(calls, 0);
});

test("blocks a state-changing request in a read-only scope", async () => {
  let calls = 0;
  const fetchFn: typeof fetch = async () => {
    calls += 1;
    return new Response("should not happen");
  };
  const scope = makeScope({ readOnly: true });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({
    method: "POST",
    url: "https://example.test/",
    body: "{}",
  });
  assert.equal(outcome.ok, false);
  assert.match(outcome.error ?? "", /not allowed|read-only/);
  assert.equal(calls, 0);
});

test("does not follow an external redirect", async () => {
  const calls: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    calls.push(String(input));
    return new Response(null, {
      status: 302,
      headers: { location: "https://evil.test/next" },
    });
  };
  const { client } = await makeClient({ fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/start" });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.response?.status, 302);
  assert.equal(outcome.redirects.length, 1);
  assert.equal(outcome.redirects[0].followed, false);
  assert.equal(calls.length, 1);
});

test("follows an in-scope redirect and re-checks scope on the next hop", async () => {
  const calls: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    if (url === "https://example.test/start") {
      return new Response(null, { status: 302, headers: { location: "/next" } });
    }
    return new Response("done", { status: 200 });
  };
  const { client } = await makeClient({ fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/start" });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.response?.status, 200);
  assert.equal(outcome.response?.bodyText, "done");
  assert.deepEqual(calls, ["https://example.test/start", "https://example.test/next"]);
  assert.equal(outcome.redirects[0].followed, true);
});

test("blocks a redirect that lands on a denied path", async () => {
  const calls: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    calls.push(String(input));
    return new Response(null, { status: 302, headers: { location: "/internal" } });
  };
  const scope = makeScope({ deny: [{ host: "example.test", paths: ["/internal"] }] });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/start" });
  assert.equal(outcome.ok, false);
  assert.match(outcome.error ?? "", /deny/);
  assert.equal(calls.length, 1);
});

test("stops at the configured redirect limit", async () => {
  const fetchFn: typeof fetch = async (input) => {
    const url = String(input);
    return new Response(null, {
      status: 302,
      headers: { location: `${url}/again` },
    });
  };
  const scope = makeScope({ policy: { maxRedirects: 2 } });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({ method: "GET", url: "https://example.test/start" });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.response?.status, 302);
  assert.equal(outcome.redirects.length, 3);
  assert.equal(outcome.redirects[2].followed, false);
  assert.match(outcome.redirects[2].reason ?? "", /max redirects/);
});

test("converts a 303 redirect to GET and drops the body", async () => {
  const methods: string[] = [];
  const bodies: boolean[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    methods.push(init?.method ?? "");
    bodies.push(init?.body != null);
    const url = String(input);
    if (url === "https://example.test/start") {
      return new Response(null, { status: 303, headers: { location: "/next" } });
    }
    return new Response("ok", { status: 200 });
  };
  const scope = makeScope({
    stateChanging: { mode: "allow", allow: ["POST /"] },
  });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({
    method: "POST",
    url: "https://example.test/start",
    body: "payload",
  });
  assert.equal(outcome.ok, true, outcome.error);
  assert.deepEqual(methods, ["POST", "GET"]);
  assert.deepEqual(bodies, [true, false]);
});

test("strips authorization headers when redirecting to a different host", async () => {
  const calls: Array<Record<string, string> | undefined> = [];
  const fetchFn: typeof fetch = async (input, init) => {
    calls.push(init?.headers as Record<string, string> | undefined);
    const url = String(input);
    if (url === "https://example.test/start") {
      return new Response(null, {
        status: 302,
        headers: { location: "https://api.test/next" },
      });
    }
    return new Response("ok", { status: 200 });
  };
  const scope = makeScope({
    targets: [
      { host: "example.test", scheme: "https", port: 443, paths: ["/"] },
      { host: "api.test", scheme: "https", port: 443, paths: ["/"] },
    ],
  });
  const { client } = await makeClient({ scope, fetchFn });
  const outcome = await client.request({
    method: "GET",
    url: "https://example.test/start",
    headers: { Authorization: "Bearer secret" },
  });
  assert.equal(outcome.ok, true);
  assert.equal(calls[0]?.authorization, "Bearer secret");
  assert.equal(calls[1]?.authorization, undefined);
});

test("caps the response body and reports the real size", async () => {
  const bytes = new Uint8Array(64).fill(65);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  const fetchFn: typeof fetch = async () => new Response(stream, { status: 200 });
  const { client } = await makeClient({ fetchFn, maxResponseBodyBytes: 16 });
  const outcome = await client.request({ method: "GET", url: "https://example.test/" });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.response?.truncated, true);
  assert.equal(outcome.response?.bodyText.length, 16);
  assert.equal(outcome.response?.bodyBytes, 64);
});

test("writes a guardrail audit entry for a blocked request", async () => {
  const fetchFn: typeof fetch = async () => new Response("should not happen");
  const { client, audit } = await makeClient({ fetchFn });
  await client.request({ method: "GET", url: "https://evil.test/" });
  const entries = audit.list();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].event, "guardrail");
  assert.equal(entries[0].decision, "deny");
});
