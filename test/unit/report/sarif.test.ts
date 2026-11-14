import { test } from "node:test";
import assert from "node:assert/strict";
import { renderSarif } from "../../../src/report/sarif.js";
import { makeFinding, makeReport } from "./helpers.js";

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  properties: Record<string, unknown>;
}

interface SarifLog {
  $schema: string;
  version: string;
  runs: Array<{
    tool: { driver: { name: string; informationUri: string; rules: unknown[] } };
    results: SarifResult[];
  }>;
}

test("renderSarif emits a valid 2.1.0 log with only reported findings", () => {
  const sarif = JSON.parse(renderSarif(makeReport())) as SarifLog;

  assert.equal(sarif.version, "2.1.0");
  assert.match(sarif.$schema, /sarif-2\.1\.0\.json/);
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, "Anbu");
  assert.equal(sarif.runs[0].results.length, 2);
  assert.ok(
    sarif.runs[0].results.every(
      (result) => result.properties.status === "confirmed" || result.properties.status === "probable",
    ),
  );
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2);
});

test("renderSarif maps severity to SARIF levels", () => {
  const sarif = JSON.parse(renderSarif(makeReport())) as SarifLog;
  const levels = sarif.runs[0].results.map((result) => result.level);

  assert.ok(levels.includes("error"));
  assert.ok(levels.includes("warning"));
});

test("renderSarif maps informational severity to none and includes discarded on request", () => {
  const informational = makeReport({
    findings: [makeFinding({ severity: "informational", status: "probable" })],
  });
  const sarif = JSON.parse(renderSarif(informational)) as SarifLog;
  assert.equal(sarif.runs[0].results[0].level, "none");

  const withDiscarded = JSON.parse(renderSarif(makeReport(), { includeDiscarded: true })) as SarifLog;
  assert.equal(withDiscarded.runs[0].results.length, 3);
});

test("renderSarif points each result at the affected URL", () => {
  const sarif = JSON.parse(renderSarif(makeReport())) as SarifLog;
  const uris = sarif.runs[0].results.map(
    (result) => result.locations[0].physicalLocation.artifactLocation.uri,
  );
  assert.ok(uris.every((uri) => uri.startsWith("https://example.test/")));
});
