import test from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { OwaspCategory, Scope } from "../../src/model/scope.js";
import { OWASP_CATEGORIES } from "../../src/model/scope.js";
import { runPentest } from "../../src/agent/loop.js";
import { startTargetFixture } from "./fixture.js";
import { compareBaseline, loadBaseline } from "./baseline.js";
import { writeScopeFile } from "../integration/helpers.js";

const here = dirname(fileURLToPath(import.meta.url));

function targetScope(port: number): Scope {
  return {
    version: 1,
    name: "M6 local target fixture",
    authorization: {
      reference: "TARGET-LOCAL-001",
      owner: "Anbu target tests",
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2035-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN",
    },
    targets: [
      {
        host: "127.0.0.1",
        scheme: "http",
        port,
        paths: ["/"],
        methods: ["GET", "HEAD", "OPTIONS"],
      },
    ],
    deny: [],
    testClasses: [...OWASP_CATEGORIES] as OwaspCategory[],
    readOnly: true,
    policy: {
      maxRequests: 2000,
      maxDurationMinutes: 5,
      maxModelTurns: 10,
      maxFindingsPerCategory: 100,
      maxBodyBytes: 65_536,
      maxRedirects: 3,
      followExternalRedirects: false,
      requestsPerSecondPerHost: 1000,
    },
  };
}

/** Wrap fetch so any request outside the local fixture fails loudly. */
function containedFetch(baseUrl: string, requestedUrls: string[]): typeof fetch {
  const realFetch = globalThis.fetch;
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    requestedUrls.push(url);
    if (url !== baseUrl && !url.startsWith(`${baseUrl}/`)) {
      throw new Error(`refusing a request outside the authorized fixture: ${url}`);
    }
    return realFetch(input, init);
  }) as typeof fetch;
}

test("the local fixture baseline reproduces with no unexplained findings or misses", async () => {
  const fixture = await startTargetFixture();
  try {
    const evidenceDir = await mkdtemp(join(tmpdir(), "anbu-target-baseline-"));
    const scopePath = await writeScopeFile(targetScope(fixture.port));
    const requestedUrls: string[] = [];

    const result = await runPentest({
      scopePath,
      modelEnabled: false,
      evidenceDir,
      maxDepth: 1,
      maxUrls: 10,
      maxReproductions: 100,
      env: () => "target-test-token",
      fetchFn: containedFetch(fixture.baseUrl, requestedUrls),
    });

    assert.equal(
      result.ok,
      true,
      result.errors === undefined ? "run failed" : result.errors.join("; "),
    );
    assert.equal(result.stopReason, "completed");
    assert.equal(result.modelAvailable, false);
    assert.ok(result.budgets.usedRequests > 0);
    assert.ok(requestedUrls.length > 0, "the engine must actually exercise the fixture");

    assert.equal(result.report.audit.integrity, "ok");
    assert.equal(result.coverage.length, 10);
    assert.ok(result.coverage.every((entry) => entry.status === "covered"));

    for (const finding of result.findings.filter((candidate) => candidate.status !== "discarded")) {
      assert.ok(finding.evidence.length > 0, `${finding.checkId} finding has no evidence`);
      assert.ok(finding.verification !== undefined, `${finding.checkId} finding was not verified`);
      assert.equal(finding.status, "confirmed", `${finding.checkId}: ${finding.title}`);
    }

    const baseline = await loadBaseline(join(here, "baselines", "local-fixture.json"));
    const comparison = compareBaseline(result.report, baseline);
    assert.equal(comparison.ok, true, JSON.stringify(comparison, null, 2));
    assert.deepEqual(comparison.reportedCheckIds, [...baseline.expectedReportedCheckIds].sort());

    for (const name of ["report.json", "report.md", "report.sarif"]) {
      await access(join(result.reportDir, name));
    }
  } finally {
    await fixture.close();
  }
});
