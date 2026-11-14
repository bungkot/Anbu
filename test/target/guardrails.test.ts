import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Report } from "../../src/model/report.js";
import type { OwaspCategory, Scope } from "../../src/model/scope.js";
import { OWASP_CATEGORIES } from "../../src/model/scope.js";
import { runPentest } from "../../src/agent/loop.js";
import { compareBaseline, loadBaseline } from "./baseline.js";
import { writeScopeFile } from "../integration/helpers.js";

const here = dirname(fileURLToPath(import.meta.url));

function externalScope(): Scope {
  return {
    version: 1,
    name: "M6 authorized external target (example only)",
    authorization: {
      reference: "ALTORO-2026-001",
      owner: "Example asset owner",
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2035-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN_MISSING_FOR_TEST",
    },
    targets: [
      {
        host: "demo.testfire.net",
        scheme: "https",
        port: 443,
        paths: ["/"],
        methods: ["GET", "HEAD", "OPTIONS"],
      },
    ],
    deny: [],
    testClasses: [...OWASP_CATEGORIES] as OwaspCategory[],
    readOnly: true,
    policy: {
      maxRequests: 500,
      requestsPerSecondPerHost: 5,
      followExternalRedirects: false,
    },
  };
}

test("the external Altoro baseline refuses to start without a resolved authorization token", async () => {
  const scopePath = await writeScopeFile(externalScope());
  let fetchCalls = 0;
  const networkDisabled: typeof fetch = async () => {
    fetchCalls += 1;
    throw new Error("network access is disabled in this test");
  };

  const result = await runPentest({
    scopePath,
    modelEnabled: false,
    evidenceDir: await mkdtemp(join(tmpdir(), "anbu-target-guard-")),
    fetchFn: networkDisabled,
    env: () => undefined,
  });

  assert.equal(result.ok, false);
  assert.match((result.errors ?? []).join("\n"), /authorization token is missing or empty/);
  assert.equal(fetchCalls, 0, "no request may be sent before authorization resolves");
});

test("a pending-authorization baseline is never reported as passing", async () => {
  const baseline = await loadBaseline(join(here, "baselines", "altoro-mutual.json"));
  assert.equal(baseline.status, "pending-authorization");

  const comparison = compareBaseline({ findings: [] } as unknown as Report, baseline);
  assert.equal(comparison.ok, false);
  assert.match(comparison.reason ?? "", /has not been recorded/);
});
