import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { intake } from "../../src/intake.js";
import { makeScope } from "./helpers.js";

const now = new Date("2026-06-01T00:00:00Z");

async function writeScope(value: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-intake-"));
  const path = join(dir, "scope.json");
  await writeFile(path, JSON.stringify(value), "utf8");
  return path;
}

test("intake accepts a valid scope", async () => {
  const path = await writeScope(makeScope());
  const result = await intake(path, now, () => "secret");
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.scope.name, "test scope");
});

test("intake reports an unreadable scope file", async () => {
  const result = await intake(
    join(tmpdir(), "anbu-does-not-exist", "scope.json"),
    now,
    () => "secret",
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /cannot read/);
});

test("intake reports invalid JSON", async () => {
  const dir = await mkdtemp(join(tmpdir(), "anbu-intake-"));
  const path = join(dir, "scope.json");
  await writeFile(path, "{ not json", "utf8");
  const result = await intake(path, now, () => "secret");
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /not valid JSON/);
});

test("intake refuses an unsupported scope version", async () => {
  const path = await writeScope({ ...makeScope(), version: 2 });
  const result = await intake(path, now, () => "secret");
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /version/);
});

test("intake refuses an expired authorization", async () => {
  const scope = makeScope({
    authorization: {
      reference: "TEST-001",
      owner: "Test Owner",
      validFrom: "2019-01-01T00:00:00Z",
      validUntil: "2020-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN",
    },
  });
  const path = await writeScope(scope);
  const result = await intake(path, now, () => "secret");
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /expired/);
});

test("intake refuses a missing authorization token", async () => {
  const path = await writeScope(makeScope());
  const result = await intake(path, now, () => undefined);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors.join("\n"), /token/);
});
