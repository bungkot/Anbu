import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildSystemPrompt,
  buildUserPrompt,
  fenceTargetData,
  redactPromptUrl,
  sanitizeText,
} from "../../../src/agent/prompts.js";
import type { AttackSurfaceSummary } from "../../../src/recon.js";
import { makeScope } from "../helpers.js";
import { makeRunContext } from "./helpers.js";

test("sanitizeText removes control characters", () => {
  const cleaned = sanitizeText("bad\u0000value\u001Fend");
  assert.equal(cleaned, "badvalueend");
});

test("sanitizeText truncates long input with an ellipsis", () => {
  const cleaned = sanitizeText("a".repeat(500), 100);
  assert.equal(cleaned.length, 101);
  assert.ok(cleaned.endsWith("…"));
});

test("redactPromptUrl redacts credential-like query keys and drops the fragment", () => {
  const redacted = redactPromptUrl(
    "https://example.test/search?q=1&token=abc123&page=2#fragment",
  );
  assert.ok(redacted.includes("q=1"));
  assert.ok(redacted.includes("page=2"));
  assert.ok(redacted.includes("token=%5BREDACTED%5D") || redacted.includes("token=[REDACTED]"));
  assert.ok(!redacted.includes("abc123"));
  assert.ok(!redacted.includes("fragment"));
});

test("redactPromptUrl returns unparseable values unchanged", () => {
  assert.equal(redactPromptUrl("not a url"), "not a url");
});

test("fenceTargetData marks untrusted content as data", () => {
  const fenced = fenceTargetData("attack-surface", "secret content");
  assert.equal(fenced, '<target-data id="attack-surface">\nsecret content\n</target-data>');
});

test("buildSystemPrompt declares the closed action schema and data fencing rule", () => {
  const prompt = buildSystemPrompt();
  assert.ok(prompt.includes("run_check"));
  assert.ok(prompt.includes("http_request"));
  assert.ok(prompt.includes("halt"));
  assert.ok(prompt.includes("<target-data>"));
});

test("buildUserPrompt redacts credentials and fences target-derived content", async () => {
  const { ctx } = await makeRunContext({
    scope: makeScope({
      testClasses: ["A05"],
      targets: [
        {
          host: "example.test",
          scheme: "https",
          port: 443,
          paths: ["/?token=super-secret"],
          methods: ["GET", "HEAD", "OPTIONS", "POST"],
        },
      ],
    }),
  });
  const summary: AttackSurfaceSummary = {
    targets: ["https://example.test"],
    startUrls: ["https://example.test/?token=super-secret"],
    urls: ["https://example.test/search?token=super-secret&q=1"],
    forms: [
      {
        pageUrl: "https://example.test/",
        action: "https://example.test/login",
        method: "POST",
        parameters: ["username", "password"],
      },
    ],
    assets: [],
    technologies: [{ name: "jquery", evidence: "https://example.test/jquery.js" }],
    blocked: [],
    requests: 3,
    truncated: false,
    maxDepth: 2,
    maxUrls: 50,
  };
  ctx.attackSurface = summary;
  ctx.recordResult({
    tool: "http_request",
    ok: true,
    url: "https://example.test/?access_token=super-secret",
    status: 200,
  });

  const prompt = buildUserPrompt(ctx);

  assert.ok(!prompt.includes("super-secret"));
  assert.match(prompt, /redacted/i);
  assert.ok(prompt.includes('<target-data id="attack-surface">'));
  assert.ok(prompt.includes('<target-data id="recent-results">'));
  assert.ok(prompt.includes("A05 Injection"));
  assert.ok(prompt.includes("Remaining budget:"));
});
