import { test } from "node:test";
import assert from "node:assert/strict";
import { parseScope } from "../../src/model/scope.js";
import { evaluateScope } from "../../src/guardrails/scope.js";
import { makeScope } from "./helpers.js";

function request(method: string, url: string): { method: string; url: string } {
  return { method, url };
}

test("parseScope accepts a valid scope", () => {
  const result = parseScope(makeScope());
  assert.equal(result.ok, true);
});

test("parseScope rejects a non-object", () => {
  const result = parseScope(null);
  assert.equal(result.ok, false);
});

test("parseScope rejects an unsupported version", () => {
  const result = parseScope({ ...makeScope(), version: 2 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /version/);
});

test("parseScope rejects empty targets", () => {
  const result = parseScope(makeScope({ targets: [] }));
  assert.equal(result.ok, false);
});

test("parseScope rejects an invalid test class", () => {
  const result = parseScope({ ...makeScope(), testClasses: ["A99"] });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /testClasses/);
});

test("parseScope defaults testClasses to all categories", () => {
  const result = parseScope({ ...makeScope(), testClasses: undefined });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.value.testClasses.length, 10);
});

test("parseScope rejects a deny entry without host or cidr", () => {
  const result = parseScope({ ...makeScope(), deny: [{ paths: ["/admin"] }] });
  assert.equal(result.ok, false);
});

test("evaluateScope allows an in-scope GET", () => {
  const decision = evaluateScope(makeScope(), request("GET", "https://example.test/app"));
  assert.equal(decision.allowed, true);
});

test("evaluateScope blocks an out-of-scope host", () => {
  const decision = evaluateScope(makeScope(), request("GET", "https://evil.test/app"));
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason, /not covered/);
});

test("deny wins over an allowed target", () => {
  const scope = makeScope({ deny: [{ host: "example.test", paths: ["/admin"] }] });
  const decision = evaluateScope(scope, request("GET", "https://example.test/admin/delete"));
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.match(decision.reason, /deny/);
});

test("deny by wildcard host", () => {
  const scope = makeScope({ deny: [{ host: "*.example.test" }] });
  const decision = evaluateScope(scope, request("GET", "https://foo.example.test/"));
  assert.equal(decision.allowed, false);
});

test("deny by CIDR for an IP-literal host", () => {
  const scope = makeScope({
    targets: [{ host: "203.0.113.10", scheme: "http", port: 80, paths: ["/"] }],
    deny: [{ cidr: "203.0.113.0/24" }],
  });
  const decision = evaluateScope(scope, request("GET", "http://203.0.113.10/"));
  assert.equal(decision.allowed, false);
});

test("path prefix must match", () => {
  const scope = makeScope({
    targets: [{ host: "example.test", scheme: "https", port: 443, paths: ["/app"] }],
  });
  assert.equal(evaluateScope(scope, request("GET", "https://example.test/app/x")).allowed, true);
  assert.equal(evaluateScope(scope, request("GET", "https://example.test/application")).allowed, false);
});

test("method must be allowed", () => {
  const scope = makeScope({
    targets: [
      { host: "example.test", scheme: "https", port: 443, paths: ["/"], methods: ["GET"] },
    ],
  });
  assert.equal(evaluateScope(scope, request("POST", "https://example.test/")).allowed, false);
});

test("read-only scope blocks state-changing methods", () => {
  const scope = makeScope({ readOnly: true });
  assert.equal(evaluateScope(scope, request("POST", "https://example.test/")).allowed, false);
});

test("wildcard target host", () => {
  const scope = makeScope({
    targets: [{ host: "*.example.test", scheme: "https", port: 443, paths: ["/"] }],
  });
  assert.equal(evaluateScope(scope, request("GET", "https://foo.example.test/")).allowed, true);
  assert.equal(evaluateScope(scope, request("GET", "https://example.test/")).allowed, false);
});

test("wrong port is out of scope", () => {
  const decision = evaluateScope(makeScope(), request("GET", "https://example.test:8443/"));
  assert.equal(decision.allowed, false);
});
