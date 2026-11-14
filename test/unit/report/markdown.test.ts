import { test } from "node:test";
import assert from "node:assert/strict";
import { renderMarkdown } from "../../../src/report/markdown.js";
import { makeFinding, makeReport } from "./helpers.js";

test("renderMarkdown includes methodology, coverage, budgets, and the audit log", () => {
  const markdown = renderMarkdown(makeReport());

  assert.match(markdown, /# Anbu Pentest Report/);
  assert.match(markdown, /OWASP Top 10:2025/);
  assert.match(markdown, /Deterministic checks:\*\* 20/);
  assert.match(markdown, /\| A05 \| Injection \| covered \| 2 \| 3 \|/);
  assert.match(markdown, /\| Requests \| 120 \| 800 \|/);
  assert.match(markdown, /\| Model turns \| 10 \| 120 \|/);
  assert.match(markdown, /## Audit log/);
  assert.match(markdown, /Integrity:\*\* ok/);
  assert.match(markdown, /run\.start/);
});

test("renderMarkdown omits discarded findings by default and includes them on request", () => {
  const filtered = renderMarkdown(makeReport());
  assert.match(filtered, /SQL error message reflected after an injection probe/);
  assert.doesNotMatch(filtered, /Discarded candidate/);
  assert.match(filtered, /1 candidate\(s\) were withheld/);

  const all = renderMarkdown(makeReport(), { includeDiscarded: true });
  assert.match(all, /Discarded candidate/);
  assert.doesNotMatch(all, /were withheld/);
});

test("renderMarkdown renders evidence, reproduction, remediation, and verification", () => {
  const markdown = renderMarkdown(makeReport());
  assert.match(markdown, /`sha256:evidence`/);
  assert.match(markdown, /Send GET https:\/\/example\.test\/search/);
  assert.match(markdown, /Use parameterized queries/);
  assert.match(markdown, /Verification:\*\* confirmed/);
});

test("renderMarkdown escapes pipes in target-derived table cells", () => {
  const report = makeReport({
    findings: [makeFinding({ affected: { url: "https://example.test/a|b" } })],
  });
  const markdown = renderMarkdown(report);
  assert.match(markdown, /a\\\|b/);
});
