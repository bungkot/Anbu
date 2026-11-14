import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveToken, validateAuthorization } from "../../src/guardrails/authorization.js";
import { makeScope } from "./helpers.js";

const scope = makeScope();
const now = new Date("2026-06-01T00:00:00Z");

test("valid authorization with env token", () => {
  const status = validateAuthorization(scope.authorization, now, () => "secret");
  assert.equal(status.ok, true);
  assert.equal(status.reference, "TEST-001");
  assert.equal(status.expiresAt, scope.authorization.validUntil);
});

test("expired authorization is refused", () => {
  const status = validateAuthorization(
    scope.authorization,
    new Date("2031-01-01T00:00:00Z"),
    () => "secret",
  );
  assert.equal(status.ok, false);
  if (!status.ok) assert.match(status.reason ?? "", /expired/);
});

test("not-yet-valid authorization is refused", () => {
  const status = validateAuthorization(
    scope.authorization,
    new Date("2019-01-01T00:00:00Z"),
    () => "secret",
  );
  assert.equal(status.ok, false);
  if (!status.ok) assert.match(status.reason ?? "", /not yet valid/);
});

test("missing env token is refused", () => {
  const status = validateAuthorization(scope.authorization, now, () => undefined);
  assert.equal(status.ok, false);
  if (!status.ok) assert.match(status.reason ?? "", /token/);
});

test("literal token resolves", () => {
  const status = validateAuthorization(
    { ...scope.authorization, token: "literal-token" },
    now,
    () => undefined,
  );
  assert.equal(status.ok, true);
});

test("resolveToken reads env references only", () => {
  assert.equal(
    resolveToken("env:FOO", (name) => (name === "FOO" ? "bar" : undefined)),
    "bar",
  );
  assert.equal(
    resolveToken("env:MISSING", () => undefined),
    undefined,
  );
  assert.equal(
    resolveToken("literal", () => undefined),
    "literal",
  );
});
