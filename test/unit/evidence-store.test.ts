import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EvidenceStore } from "../../src/store/evidence-store.js";

async function makeStore(options?: { maxArtifactBytes?: number }) {
  const rootDir = await mkdtemp(join(tmpdir(), "anbu-evidence-"));
  const store = new EvidenceStore({ rootDir, ...options });
  return { store, rootDir };
}

test("capture writes a content-addressed artifact", async () => {
  const { store } = await makeStore();
  const result = await store.capture({
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: {
      status: 200,
      headers: { "content-type": "text/html" },
      body: "<html></html>",
    },
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.match(result.evidenceId, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.path, `artifacts/${result.sha256}.json`);

  const artifact = await store.get(result.evidenceId);
  assert.equal(artifact?.id, result.evidenceId);
  assert.equal(artifact?.sha256, result.sha256);
  assert.equal(artifact?.response.status, 200);
  assert.equal(artifact?.sizeBytes, result.sizeBytes);
  assert.equal(await store.verify(result.evidenceId), true);
});

test("redacts credentials, cookies, query tokens, and body secrets", async () => {
  const { store } = await makeStore();
  const result = await store.capture({
    request: {
      method: "get",
      url: "https://example.test/login?token=secret&page=2&api_key=abc",
      headers: {
        authorization: "Bearer supersecret",
        cookie: "session=abc; theme=dark",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        username: "bob",
        password: "hunter2",
        nested: { access_token: "tok" },
      }),
    },
    response: {
      status: 200,
      headers: {
        "set-cookie": "sessionid=abc123; Path=/; HttpOnly",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ok: true, token: "abc", note: "Bearer abc.def" }),
    },
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  const artifact = await store.get(result.evidenceId);
  assert.ok(artifact);

  const redactedUrl = new URL(artifact.request.url);
  assert.equal(redactedUrl.searchParams.get("token"), "[REDACTED]");
  assert.equal(redactedUrl.searchParams.get("page"), "2");
  assert.equal(redactedUrl.searchParams.get("api_key"), "[REDACTED]");

  assert.equal(artifact.request.method, "GET");
  assert.equal(artifact.request.headers.authorization, "[REDACTED]");
  assert.equal(artifact.request.headers.cookie, "session=[REDACTED]; theme=[REDACTED]");
  assert.equal(artifact.response.headers["set-cookie"], "sessionid=[REDACTED]; Path=/; HttpOnly");

  const requestBody = JSON.parse(artifact.request.body ?? "{}") as Record<string, unknown>;
  assert.equal(requestBody.username, "bob");
  assert.equal(requestBody.password, "[REDACTED]");
  assert.equal((requestBody.nested as Record<string, unknown>).access_token, "[REDACTED]");

  const responseBody = JSON.parse(artifact.response.body ?? "{}") as Record<string, unknown>;
  assert.equal(responseBody.token, "[REDACTED]");
  assert.match(String(responseBody.note), /Bearer \[REDACTED\]/);
  assert.equal(
    artifact.response.bodyBytes,
    Buffer.byteLength(JSON.stringify({ ok: true, token: "abc", note: "Bearer abc.def" }), "utf8"),
  );
});

test("redacts a credential assignment at the very start of a text body", async () => {
  const { store } = await makeStore();
  const result = await store.capture({
    request: {
      method: "GET",
      url: "https://example.test/leak",
      headers: { "content-type": "text/plain; charset=utf-8" },
    },
    response: {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: "access_token=smoke-secret-value&note=safe",
    },
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  const artifact = await store.get(result.evidenceId);
  assert.ok(artifact);
  assert.doesNotMatch(JSON.stringify(artifact), /smoke-secret-value/);
  assert.match(artifact.response.body ?? "", /access_token=\[REDACTED\]/);
  assert.match(artifact.response.body ?? "", /note=safe/);
});

test("refuses artifacts larger than the size cap", async () => {
  const { store } = await makeStore({ maxArtifactBytes: 64 });
  const result = await store.capture({
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: { status: 200, body: "x".repeat(256) },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.match(result.error, /exceeding the 64-byte cap/);
});

test("returns undefined for missing, malformed, and tampered evidence", async () => {
  const { store, rootDir } = await makeStore();
  assert.equal(await store.get(`sha256:${"0".repeat(64)}`), undefined);
  assert.equal(await store.get("not-an-id"), undefined);
  assert.equal(await store.get("sha256:does-not-exist"), undefined);

  const result = await store.capture({
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: { status: 200, body: "original" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;

  const artifact = await store.get(result.evidenceId);
  assert.ok(artifact);
  const tampered = { ...artifact, response: { ...artifact.response, status: 500 } };
  await writeFile(join(rootDir, result.path), JSON.stringify(tampered), "utf8");

  assert.equal(await store.get(result.evidenceId), undefined);
  assert.equal(await store.verify(result.evidenceId), false);
});

test("compares identical and changed artifacts", async () => {
  const { store } = await makeStore();
  const input = {
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: {
      status: 200,
      headers: { "content-type": "text/html", "x-frame-options": "DENY" },
      body: "<html>same</html>",
    },
  };

  const first = await store.capture(input);
  const second = await store.capture(input);
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  if (!first.ok || !second.ok) return;

  const same = await store.compare(first.evidenceId, second.evidenceId);
  assert.equal(same.ok, true);
  if (!same.ok) return;
  assert.equal(same.comparison.status.changed, false);
  assert.deepEqual(same.comparison.headers, []);
  assert.equal(same.comparison.body.changed, false);

  const changed = await store.capture({
    request: input.request,
    response: {
      status: 500,
      headers: { "content-type": "text/html", "x-frame-options": "SAMEORIGIN" },
      body: "<html>different</html>",
    },
  });
  assert.equal(changed.ok, true);
  if (!changed.ok) return;

  const diff = await store.compare(changed.evidenceId, first.evidenceId);
  assert.equal(diff.ok, true);
  if (!diff.ok) return;
  assert.equal(diff.comparison.status.changed, true);
  assert.equal(diff.comparison.status.candidate, 500);
  assert.equal(diff.comparison.status.baseline, 200);
  assert.ok(
    diff.comparison.headers.some(
      (header) =>
        header.name === "x-frame-options" &&
        header.candidate === "SAMEORIGIN" &&
        header.baseline === "DENY",
    ),
  );
  assert.equal(diff.comparison.body.changed, true);
  assert.ok(diff.comparison.body.candidateBytes > diff.comparison.body.baselineBytes);
});

test("reports a safe error when comparison evidence is missing", async () => {
  const { store } = await makeStore();
  const result = await store.capture({
    request: { method: "GET", url: "https://example.test/", headers: {} },
    response: { status: 200, body: "ok" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;

  const missing = await store.compare(result.evidenceId, "sha256:" + "0".repeat(64));
  assert.equal(missing.ok, false);
  if (missing.ok) return;
  assert.match(missing.error, /baseline evidence not found/);
});

test("parses stored HTML into headers, cookies, forms, links, assets, and technologies", async () => {
  const { store } = await makeStore();
  const page = `<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.5">
<script src="/assets/react.min.js"></script>
</head><body>
<a href="/next">next</a>
<form action="/login" method="post">
  <input name="username">
  <input name="password" type="password">
</form>
<img src="/assets/logo.png">
</body></html>`;

  const result = await store.capture({
    request: { method: "GET", url: "https://example.test/page", headers: {} },
    response: {
      status: 200,
      headers: {
        "content-type": "text/html",
        "set-cookie": "sessionid=abc123; Path=/; HttpOnly",
      },
      body: page,
    },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;

  const parsed = await store.parse(result.evidenceId);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  assert.equal(parsed.facts.url, "https://example.test/page");
  assert.equal(parsed.facts.status, 200);
  assert.equal(parsed.facts.headers["content-type"], "text/html");
  assert.deepEqual(parsed.facts.cookies, ["sessionid"]);
  assert.deepEqual(parsed.facts.forms, [
    {
      pageUrl: "https://example.test/page",
      action: "https://example.test/login",
      method: "POST",
      parameters: ["username", "password"],
    },
  ]);
  assert.deepEqual(parsed.facts.links, ["https://example.test/next"]);
  assert.ok(
    parsed.facts.assets.some(
      (asset) =>
        asset.type === "script" && asset.url === "https://example.test/assets/react.min.js",
    ),
  );
  assert.ok(
    parsed.facts.assets.some(
      (asset) => asset.type === "image" && asset.url === "https://example.test/assets/logo.png",
    ),
  );
  const technologies = parsed.facts.technologies.map((marker) => marker.name);
  assert.ok(technologies.includes("react"));
  assert.ok(technologies.includes("generator"));
});

test("parse reports a safe error for missing evidence", async () => {
  const { store } = await makeStore();
  const parsed = await store.parse("sha256:" + "0".repeat(64));
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.match(parsed.error, /not found or invalid/);
});
