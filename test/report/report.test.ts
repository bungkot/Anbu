import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPentest } from "../../src/agent/loop.js";
import { REPORT_VERSION } from "../../src/model/report.js";
import { renderJson, renderMarkdown, renderSarif } from "../../src/report/index.js";
import { localScope, startFixture, writeScopeFile } from "../integration/helpers.js";

interface JsonFinding {
  status: string;
}

interface JsonReport {
  reportVersion: number;
  methodology: { framework: string };
  coverage: Array<{ category: string; status: string }>;
  budgets: { usedRequests: number };
  audit: { integrity: string };
  findings: JsonFinding[];
  withheldFindings: number;
}

test("rendered reports carry methodology, coverage, budgets, audit, and only reported findings", async () => {
  const fixture = await startFixture();
  try {
    const evidenceDir = await mkdtemp(join(tmpdir(), "anbu-report-e2e-"));
    const scopePath = await writeScopeFile(localScope(fixture.port));

    const result = await runPentest({
      scopePath,
      modelEnabled: false,
      evidenceDir,
      maxDepth: 1,
      maxUrls: 10,
      env: () => "test-token",
    });
    assert.equal(result.ok, true);

    const defaultJson = JSON.parse(renderJson(result.report)) as JsonReport;
    assert.equal(defaultJson.reportVersion, REPORT_VERSION);
    assert.equal(defaultJson.methodology.framework, "OWASP Top 10:2025");
    assert.equal(defaultJson.coverage.length, 10);
    assert.ok(defaultJson.budgets.usedRequests > 0);
    assert.equal(defaultJson.audit.integrity, "ok");
    assert.ok(
      defaultJson.findings.every(
        (finding) => finding.status === "confirmed" || finding.status === "probable",
      ),
    );
    assert.ok(defaultJson.withheldFindings >= 1);

    const allJson = JSON.parse(renderJson(result.report, { includeDiscarded: true })) as JsonReport;
    assert.equal(allJson.findings.length, result.report.findings.length);

    const markdown = renderMarkdown(result.report);
    assert.match(markdown, /OWASP Top 10:2025/);
    assert.doesNotMatch(markdown, /SQL error message reflected/);

    const markdownAll = renderMarkdown(result.report, { includeDiscarded: true });
    assert.match(markdownAll, /SQL error message reflected/);

    const sarif = JSON.parse(renderSarif(result.report)) as {
      version: string;
      runs: Array<{ results: unknown[] }>;
    };
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].results.length, defaultJson.findings.length);
  } finally {
    await fixture.close();
  }
});
