import { test } from "node:test";
import assert from "node:assert/strict";
import { renderJson } from "../../../src/report/json.js";
import { REPORT_VERSION } from "../../../src/model/report.js";
import { makeReport } from "./helpers.js";

test("renderJson includes the report version, methodology, audit, and coverage", () => {
  const parsed = JSON.parse(renderJson(makeReport())) as Record<string, unknown>;

  assert.equal(parsed.reportVersion, REPORT_VERSION);
  assert.equal(parsed.runId, "run-1");
  assert.equal(parsed.scopeReference, "PENTEST-2026-001");
  assert.equal(typeof parsed.methodology, "object");
  assert.equal(typeof parsed.audit, "object");
  assert.ok(Array.isArray(parsed.coverage));
  assert.equal(typeof parsed.budgets, "object");
});

test("renderJson reports only confirmed and probable findings by default", () => {
  const parsed = JSON.parse(renderJson(makeReport())) as {
    findings: Array<{ status: string }>;
    withheldFindings: number;
  };

  assert.equal(parsed.findings.length, 2);
  assert.ok(parsed.findings.every((finding) => finding.status === "confirmed" || finding.status === "probable"));
  assert.equal(parsed.withheldFindings, 1);
});

test("renderJson can include discarded findings", () => {
  const parsed = JSON.parse(renderJson(makeReport(), { includeDiscarded: true })) as {
    findings: Array<{ status: string }>;
    withheldFindings: number;
  };

  assert.equal(parsed.findings.length, 3);
  assert.equal(parsed.withheldFindings, 0);
});
