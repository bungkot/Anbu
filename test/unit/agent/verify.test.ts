import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFindings } from "../../../src/agent/verify.js";
import type { RunContext } from "../../../src/agent/context.js";
import { idorCheck, securityHeadersCheck, uploadCheck } from "../../../src/tools/checks/index.js";
import { makeFinding } from "../../../src/tools/checks/types.js";
import type { EvidenceRef, Finding, FindingCheckInput } from "../../../src/model/finding.js";
import { loopScope, makeFetchFn, makeRecordingApproval, makeRunContext } from "./helpers.js";

const HARDENED_HEADERS: Record<string, string> = {
  "content-type": "text/html",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=()",
  "x-content-type-options": "nosniff",
};

async function capture(
  ctx: RunContext,
  url: string,
  headers: Record<string, string> = {},
): Promise<EvidenceRef> {
  const result = await ctx.store.capture({
    request: { method: "GET", url, headers: {} },
    response: {
      status: 200,
      statusText: "OK",
      headers,
      body: "<html></html>",
      bodyBytes: 13,
      truncated: false,
      durationMs: 1,
    },
  });
  if (!result.ok) throw new Error(result.error);
  return { evidenceId: result.evidenceId, sha256: result.sha256, path: result.path };
}

function headerFinding(url: string, evidence: EvidenceRef[]): Finding {
  return makeFinding(
    securityHeadersCheck.metadata,
    {
      title: "Strict-Transport-Security header is missing",
      affected: { url },
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Set `Strict-Transport-Security` on every HTTPS response.",
    },
    evidence,
  );
}

function idorFinding(
  url: string,
  evidence: EvidenceRef[],
  checkInput?: FindingCheckInput,
): Finding {
  return makeFinding(
    idorCheck.metadata,
    {
      title: "Direct object reference became accessible with an alternate id",
      affected: { url, parameter: "token" },
      reproduction: [
        `Send GET ${url} with token=xyz using the same session and inspect the response.`,
      ],
      remediation:
        "Authorize every object lookup against the authenticated user's ownership; never rely on sequential or predictable ids.",
    },
    evidence,
    checkInput,
  );
}

/** A handler that only exposes the alternate object, so IDOR is reproducible. */
function idorFetch() {
  return makeFetchFn({
    handler: async (rawUrl) => {
      const url = rawUrl.toString();
      if (url.includes("token=abc")) {
        return new Response('{"error":"forbidden"}', {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response('{"id":"xyz","email":"victim@example.test"}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
}

test("verifyFindings confirms a finding that the originating check reproduces", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const fetch = makeFetchFn({
    handler: async () =>
      new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }),
  });
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/";
  const finding = headerFinding(url, [await capture(ctx, url)]);

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "confirmed");
  assert.equal(result[0].confidence, "confirmed");
  assert.equal(result[0].verification?.attempted, true);
  assert.match(result[0].verification?.reason ?? "", /reproduced/);
  assert.ok(ctx.audit.list().some((entry) => entry.event === "verify.confirmed"));
});

test("verifyFindings discards a candidate the check does not reproduce", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const fetch = makeFetchFn({
    handler: async () => new Response("<html></html>", { status: 200, headers: HARDENED_HEADERS }),
  });
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/";
  const finding = headerFinding(url, [await capture(ctx, url)]);

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "discarded");
  assert.equal(result[0].confidence, "unverified");
  assert.match(result[0].verification?.reason ?? "", /did not reproduce/);
  assert.ok(ctx.audit.list().some((entry) => entry.event === "verify.discarded"));
});

test("verifyFindings discards a candidate whose evidence is missing or invalid", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const { ctx } = await makeRunContext({ scope, env: () => "test-token" });
  const hex = "a".repeat(64);
  const finding = headerFinding("https://example.test/", [
    { evidenceId: `sha256:${hex}`, sha256: hex, path: "artifacts/missing.json" },
  ]);

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "discarded");
  assert.match(result[0].verification?.reason ?? "", /evidence is missing/);
});

test("verifyFindings keeps a state-changing finding probable when approval is denied", async () => {
  const scope = loopScope({ testClasses: ["A06"] });
  const fetch = makeFetchFn();
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/upload";
  const finding = makeFinding(
    uploadCheck.metadata,
    {
      title: "Unrestricted file upload",
      affected: { url },
      reproduction: ["Upload a harmless HTML file and retrieve it."],
      remediation: "Validate upload types and store files outside the web root.",
    },
    [await capture(ctx, url)],
  );
  const approval = makeRecordingApproval(false);

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
    approval: approval.provider,
  });

  assert.equal(approval.requests.length, 1);
  assert.equal(approval.requests[0].action, "verify:upload");
  assert.equal(result[0].status, "probable");
  assert.equal(result[0].verification?.attempted, false);
  assert.equal(fetch.calls.length, 0);
});

test("verifyFindings keeps a finding with an unknown originating check probable", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const { ctx } = await makeRunContext({ scope, env: () => "test-token" });
  const url = "https://example.test/";
  const finding = headerFinding(url, [await capture(ctx, url)]);
  finding.checkId = "does-not-exist";

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "probable");
  assert.match(result[0].verification?.reason ?? "", /unknown originating check/);
});

test("verifyFindings keeps a finding without an originating check probable", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const { ctx } = await makeRunContext({ scope, env: () => "test-token" });
  const url = "https://example.test/";
  const finding = headerFinding(url, [await capture(ctx, url)]);
  delete finding.checkId;

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "probable");
  assert.match(result[0].verification?.reason ?? "", /no originating check/);
});

test("verifyFindings respects the reproduction budget", async () => {
  const scope = loopScope({ testClasses: ["A02"] });
  const fetch = makeFetchFn({
    handler: async () =>
      new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }),
  });
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const firstUrl = "https://example.test/";
  const secondUrl = "https://example.test/other";
  const first = headerFinding(firstUrl, [await capture(ctx, firstUrl)]);
  const second = headerFinding(secondUrl, [await capture(ctx, secondUrl)]);

  const result = await verifyFindings({
    findings: [first, second],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
    maxReproductions: 1,
  });

  assert.equal(result[0].status, "confirmed");
  assert.equal(result[1].status, "probable");
  assert.match(result[1].verification?.reason ?? "", /budget reached/);
});

test("verifyFindings reproduces an options-based finding from its stored check input", async () => {
  const scope = loopScope({ testClasses: ["A01"] });
  const fetch = idorFetch();
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/api/account?token=abc";
  const finding = idorFinding(url, [await capture(ctx, url)], {
    parameter: "token",
    options: { alternates: ["xyz"] },
  });

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "confirmed");
  assert.equal(result[0].verification?.attempted, true);
  assert.ok(fetch.calls.some((call) => call.url.includes("token=xyz")));
});

test("verifyFindings cannot reproduce an options-based finding without stored input", async () => {
  const scope = loopScope({ testClasses: ["A01"] });
  const fetch = idorFetch();
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/api/account?token=abc";
  const finding = idorFinding(url, [await capture(ctx, url)]);

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "discarded");
  assert.match(result[0].verification?.reason ?? "", /did not reproduce/);
});

test("verifyFindings keeps a finding whose stored input was redacted probable", async () => {
  const scope = loopScope({ testClasses: ["A01"] });
  const fetch = makeFetchFn();
  const { ctx } = await makeRunContext({
    scope,
    fetchFn: fetch.fetchFn,
    env: () => "test-token",
  });
  const url = "https://example.test/api/account?token=abc";
  const finding = idorFinding(url, [await capture(ctx, url)], {
    parameter: "token",
    options: { alternates: ["[REDACTED]"] },
    redacted: true,
  });

  const result = await verifyFindings({
    findings: [finding],
    scope: ctx.scope,
    store: ctx.store,
    client: ctx.client,
    audit: ctx.audit,
  });

  assert.equal(result[0].status, "probable");
  assert.equal(result[0].verification?.attempted, false);
  assert.match(result[0].verification?.reason ?? "", /redacted/);
  assert.equal(fetch.calls.length, 0);
});
