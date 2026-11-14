import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EvidenceStore } from "../../src/store/evidence-store.js";
import { captureEvidence, compareEvidence, parseResponse } from "../../src/tools/evidence.js";

async function makeStore() {
  const rootDir = await mkdtemp(join(tmpdir(), "anbu-evidence-tools-"));
  return new EvidenceStore({ rootDir });
}

test("captureEvidence stores a sanitized artifact", async () => {
  const store = await makeStore();
  const result = await captureEvidence(store, {
    request: {
      method: "POST",
      url: "https://example.test/login",
      headers: { authorization: "Bearer secret", "content-type": "application/json" },
      body: JSON.stringify({ password: "hunter2" }),
    },
    response: {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "abc" }),
    },
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.match(result.evidenceId, /^sha256:[a-f0-9]{64}$/);

  const artifact = await store.get(result.evidenceId);
  assert.ok(artifact);
  assert.equal(artifact.request.headers.authorization, "[REDACTED]");
  assert.equal(JSON.parse(artifact.request.body ?? "{}").password, "[REDACTED]");
  assert.equal(JSON.parse(artifact.response.body ?? "{}").token, "[REDACTED]");
});

test("captureEvidence can keep raw fixtures when redaction is disabled", async () => {
  const store = await makeStore();
  const result = await captureEvidence(store, {
    redact: false,
    request: {
      method: "GET",
      url: "https://example.test/?token=abc",
      headers: { authorization: "Bearer secret" },
    },
    response: { status: 200, body: "fixture" },
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  const artifact = await store.get(result.evidenceId);
  assert.ok(artifact);
  assert.equal(artifact.request.headers.authorization, "Bearer secret");
  assert.equal(artifact.request.url, "https://example.test/?token=abc");
});

test("compareEvidence compares two captured artifacts", async () => {
  const store = await makeStore();
  const baseline = await captureEvidence(store, {
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: { status: 200, headers: { "x-test": "1" }, body: "baseline" },
  });
  assert.equal(baseline.ok, true);
  if (!baseline.ok) return;

  const candidate = await captureEvidence(store, {
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: { status: 200, headers: { "x-test": "2" }, body: "candidate" },
  });
  assert.equal(candidate.ok, true);
  if (!candidate.ok) return;

  const result = await compareEvidence(store, candidate.evidenceId, baseline.evidenceId);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.comparison.body.changed, true);
  assert.ok(
    result.comparison.headers.some(
      (header) => header.name === "x-test" && header.candidate === "2" && header.baseline === "1",
    ),
  );
});

test("parseResponse extracts facts from stored evidence", async () => {
  const store = await makeStore();
  const captured = await captureEvidence(store, {
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: {
      status: 200,
      headers: { "content-type": "text/html", "set-cookie": "sid=1; Path=/" },
      body: '<html><body><a href="/next">next</a></body></html>',
    },
  });
  assert.equal(captured.ok, true);
  if (!captured.ok) return;

  const result = await parseResponse(store, captured.evidenceId);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.facts.status, 200);
  assert.deepEqual(result.facts.cookies, ["sid"]);
  assert.deepEqual(result.facts.links, ["https://example.test/next"]);
});
