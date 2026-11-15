import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Scope } from "../../src/model/scope.js";
import { EvidenceStore } from "../../src/store/evidence-store.js";
import { localScope, makeHarness, startFixture } from "./helpers.js";

test("an out-of-scope host is blocked before any request is sent", async () => {
  const fixture = await startFixture();
  try {
    const { client } = await makeHarness(localScope(fixture.port));
    const outcome = await client.request({
      method: "GET",
      url: `http://localhost:${fixture.port}/`,
    });

    assert.equal(outcome.ok, false);
    assert.match(outcome.error ?? "", /not covered by any in-scope target/);
    assert.equal(fixture.requests.length, 0);
  } finally {
    await fixture.close();
  }
});

test("a denied path is blocked even when the host is allowed", async () => {
  const fixture = await startFixture();
  try {
    const scope = localScope(fixture.port, {
      deny: [{ host: "127.0.0.1", paths: ["/admin"] }],
    });
    const { client } = await makeHarness(scope);
    const outcome = await client.request({ method: "GET", url: `${fixture.baseUrl}/admin` });

    assert.equal(outcome.ok, false);
    assert.match(outcome.error ?? "", /deny rule/);
    assert.equal(fixture.requests.length, 0);
  } finally {
    await fixture.close();
  }
});

test("an expired authorization blocks the run", async () => {
  const fixture = await startFixture();
  try {
    const base = localScope(fixture.port);
    const scope: Scope = {
      ...base,
      authorization: { ...base.authorization, validUntil: "2021-01-01T00:00:00Z" },
    };
    const { client } = await makeHarness(scope);
    const outcome = await client.request({ method: "GET", url: `${fixture.baseUrl}/` });

    assert.equal(outcome.ok, false);
    assert.match(outcome.error ?? "", /authorization has expired/);
    assert.equal(fixture.requests.length, 0);
  } finally {
    await fixture.close();
  }
});

test("a read-only scope blocks state-changing methods", async () => {
  const fixture = await startFixture();
  try {
    const { client } = await makeHarness(localScope(fixture.port));
    const outcome = await client.request({
      method: "POST",
      url: `${fixture.baseUrl}/`,
      body: "username=test",
    });

    assert.equal(outcome.ok, false);
    // The scope guard enforces the read-only method set before the policy layer.
    assert.match(outcome.error ?? "", /method POST is not allowed for this target/);
    assert.equal(fixture.requests.length, 0);
  } finally {
    await fixture.close();
  }
});

test("an external redirect is never followed", async () => {
  const fixture = await startFixture();
  try {
    const { client } = await makeHarness(localScope(fixture.port));
    const outcome = await client.request({ method: "GET", url: `${fixture.baseUrl}/redirect` });

    assert.equal(outcome.ok, true);
    assert.equal(outcome.response?.status, 302);
    assert.equal(outcome.redirects.length, 1);
    assert.equal(outcome.redirects[0].followed, false);
    assert.equal(outcome.redirects[0].location, "http://external.invalid/leaked");
    assert.deepEqual(
      fixture.requests.map((request) => request.url),
      ["/redirect"],
    );
  } finally {
    await fixture.close();
  }
});

test("the global request budget is enforced before the second request", async () => {
  const fixture = await startFixture();
  try {
    const { client } = await makeHarness(localScope(fixture.port), { maxRequests: 1 });
    const first = await client.request({ method: "GET", url: `${fixture.baseUrl}/` });
    const second = await client.request({ method: "GET", url: `${fixture.baseUrl}/login` });

    assert.equal(first.ok, true);
    assert.equal(second.ok, false);
    assert.match(second.error ?? "", /global request budget exhausted/);
    assert.equal(fixture.requests.length, 1);
  } finally {
    await fixture.close();
  }
});

test("a per-host rate limit paces the next request instead of denying it", async () => {
  const fixture = await startFixture();
  try {
    // A fixed clock keeps the pacing amount deterministic: the third request
    // needs one full refill of a 2 req/s bucket, i.e. 500ms.
    const { client, audit } = await makeHarness(localScope(fixture.port), {
      requestsPerSecondPerHost: 2,
      rateLimitWaitMs: 1000,
      now: () => new Date("2026-01-01T00:00:00Z"),
    });
    // The burst capacity is two tokens; the third request must wait for a refill.
    assert.equal((await client.request({ method: "GET", url: `${fixture.baseUrl}/` })).ok, true);
    assert.equal((await client.request({ method: "GET", url: `${fixture.baseUrl}/` })).ok, true);
    const paced = await client.request({ method: "GET", url: `${fixture.baseUrl}/` });
    assert.equal(paced.ok, true);
    assert.equal(fixture.requests.length, 3);

    const entries = audit.list();
    assert.equal(entries.length, 3);
    assert.equal(entries[0].waitedMs, 0);
    assert.equal(entries[1].waitedMs, 0);
    assert.equal(entries[2].waitedMs, 500);
  } finally {
    await fixture.close();
  }
});

test("without a wait limit a per-host rate limit still denies immediately", async () => {
  const fixture = await startFixture();
  try {
    const { client, audit } = await makeHarness(localScope(fixture.port), {
      requestsPerSecondPerHost: 2,
    });
    assert.equal((await client.request({ method: "GET", url: `${fixture.baseUrl}/` })).ok, true);
    assert.equal((await client.request({ method: "GET", url: `${fixture.baseUrl}/` })).ok, true);
    const denied = await client.request({ method: "GET", url: `${fixture.baseUrl}/` });
    assert.equal(denied.ok, false);
    assert.match(denied.error ?? "", /per-host/);
    assert.equal(fixture.requests.length, 2);

    // Without pacing configured the limiter never waits, so the audit entries
    // carry no waitedMs field at all.
    const entries = audit.list();
    assert.equal(entries.length, 3);
    for (const entry of entries) {
      assert.equal(entry.waitedMs, undefined);
    }
  } finally {
    await fixture.close();
  }
});

test("captured evidence and audit logs never contain the leaked credential", async () => {
  const fixture = await startFixture();
  try {
    const { client, dir } = await makeHarness(localScope(fixture.port));
    const outcome = await client.request({ method: "GET", url: `${fixture.baseUrl}/leak` });
    assert.equal(outcome.ok, true);
    assert.ok(outcome.response !== undefined);

    const store = new EvidenceStore({ rootDir: dir });
    const captured = await store.capture({
      request: {
        method: "GET",
        url: `${fixture.baseUrl}/leak`,
        headers: { accept: "text/plain" },
      },
      response: {
        status: outcome.response.status,
        statusText: outcome.response.statusText,
        headers: { "content-type": "text/plain; charset=utf-8" },
        body: "access_token=smoke-secret-value&note=safe",
        bodyBytes: outcome.response.bodyBytes,
      },
    });
    assert.equal(captured.ok, true);
    assert.ok(captured.evidenceId !== undefined);

    const artifact = await store.get(captured.evidenceId);
    assert.ok(artifact !== undefined);
    assert.doesNotMatch(JSON.stringify(artifact), /smoke-secret-value/);
    assert.match(artifact.response.body ?? "", /\[REDACTED\]/);

    const auditText = await readFile(join(dir, "audit.log"), "utf8");
    assert.doesNotMatch(auditText, /smoke-secret-value/);
  } finally {
    await fixture.close();
  }
});
