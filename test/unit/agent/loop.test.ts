import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PentestOptions, PentestRunResult } from "../../../src/agent/loop.js";
import { runPentest } from "../../../src/agent/loop.js";
import type { Scope } from "../../../src/model/scope.js";
import type { RecordedFetch } from "./helpers.js";
import {
  FakePlannerTransport,
  loopScope,
  makeFetchFn,
  makeRecordingApproval,
  readAuditLines,
  writeScope,
} from "./helpers.js";

const NOW = (): Date => new Date("2026-06-01T00:00:00Z");

type LoopTestOptions = Omit<PentestOptions, "scopePath" | "transport"> & {
  scope: Scope;
  fetchHandler?: (url: string, init?: RequestInit) => Response | Promise<Response>;
  transport?: FakePlannerTransport;
};

async function runLoop(options: LoopTestOptions): Promise<{
  result: PentestRunResult;
  dir: string;
  transport: FakePlannerTransport;
  calls: RecordedFetch[];
}> {
  const { scope, fetchHandler, transport: providedTransport, ...rest } = options;
  const dir = await mkdtemp(join(tmpdir(), "anbu-loop-"));
  const scopePath = await writeScope(scope);
  const transport = providedTransport ?? new FakePlannerTransport([]);
  const fetch = makeFetchFn({ handler: fetchHandler });

  const result = await runPentest({
    modelEnabled: true,
    maxDepth: 0,
    maxUrls: 3,
    maxInputsPerCheck: 1,
    ...rest,
    scopePath,
    evidenceDir: dir,
    runId: "loop-test",
    now: NOW,
    env: () => "test-token",
    transport,
    fetchFn: fetch.fetchFn,
  });

  return { result, dir, transport, calls: fetch.calls };
}

const haltPlan = JSON.stringify({
  objective: "objective met",
  actions: [{ kind: "halt", reason: "nothing left to test" }],
});

test("refuses an invalid scope before any network call", async () => {
  const scope = loopScope({
    authorization: {
      reference: "TEST-001",
      owner: "Test Owner",
      validFrom: "2019-01-01T00:00:00Z",
      validUntil: "2020-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN",
    },
  });
  const fetch = makeFetchFn();

  const result = await runPentest({
    scopePath: await writeScope(scope),
    env: () => "test-token",
    fetchFn: fetch.fetchFn,
    modelEnabled: false,
    maxDepth: 0,
  });

  assert.equal(result.ok, false);
  assert.match(result.errors?.join("\n") ?? "", /expired/);
  assert.equal(fetch.calls.length, 0);
});

test("runs deterministic checks when the model is unavailable", async () => {
  const { result, calls, dir } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    modelEnabled: false,
  });

  assert.equal(result.ok, true);
  assert.equal(result.modelAvailable, false);
  assert.equal(result.stopReason, "completed");
  assert.ok(calls.length > 0);

  const coverage = result.coverage.find((entry) => entry.category === "A05");
  assert.equal(coverage?.status, "covered");

  const audit = await readAuditLines(dir, "loop-test");
  assert.ok(audit.some((entry) => entry.event === "check"));
  assert.ok(audit.some((entry) => entry.event === "run.end"));
});

test("a planner halt stops the loop", async () => {
  const { result, dir, transport } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    transport: new FakePlannerTransport([haltPlan]),
  });

  assert.equal(result.stopReason, "planner_halt");
  assert.equal(transport.requests.length, 1);

  const audit = await readAuditLines(dir, "loop-test");
  assert.ok(audit.some((entry) => entry.event === "planner.halt"));
});

test("budget exhaustion stops the planner loop", async () => {
  const observe = JSON.stringify({
    objective: "observe",
    actions: [{ kind: "http_request", input: { method: "GET", url: "https://example.test/" } }],
  });
  const { result, transport } = await runLoop({
    scope: loopScope({
      testClasses: ["A05"],
      policy: { requestsPerSecondPerHost: 1000, maxRequests: 800, maxModelTurns: 1 },
    }),
    transport: new FakePlannerTransport([observe]),
  });

  assert.equal(result.stopReason, "budget_exhausted");
  assert.equal(result.budgets.usedModelTurns, 1);
  assert.equal(transport.requests.length, 1);
});

test("repeated guardrail blocks stop the loop", async () => {
  const blocked = JSON.stringify({
    objective: "probe",
    actions: [{ kind: "http_request", input: { method: "GET", url: "https://evil.test/" } }],
  });
  const { result, transport, calls } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    transport: new FakePlannerTransport([blocked, blocked, blocked]),
    guardrailStreakLimit: 2,
  });

  assert.equal(result.stopReason, "guardrail_streak");
  assert.equal(transport.requests.length, 2);
  assert.ok(!calls.some((call) => call.url.includes("evil.test")));
});

test("state-changing checks require human approval before running", async () => {
  const plan = JSON.stringify({
    objective: "upload",
    actions: [
      { kind: "run_check", checkId: "upload", input: { url: "https://example.test/upload" } },
      { kind: "halt", reason: "stop" },
    ],
  });
  const approval = makeRecordingApproval(false);
  const { result, dir, calls } = await runLoop({
    scope: loopScope({ testClasses: ["A06"] }),
    transport: new FakePlannerTransport([plan]),
    approval: approval.provider,
  });

  assert.equal(approval.requests.length, 1);
  assert.equal(approval.requests[0].action, "run_check:upload");
  assert.equal(result.stopReason, "planner_halt");
  assert.ok(!result.findings.some((finding) => /upload/i.test(finding.title)));
  assert.ok(!calls.some((call) => call.method === "POST"));

  const audit = await readAuditLines(dir, "loop-test");
  assert.ok(audit.some((entry) => entry.event === "approval.denied"));
});

test("granting approval does not bypass the read-only policy", async () => {
  const plan = JSON.stringify({
    objective: "upload",
    actions: [
      { kind: "run_check", checkId: "upload", input: { url: "https://example.test/upload" } },
      { kind: "halt", reason: "stop" },
    ],
  });
  const approval = makeRecordingApproval(true);
  const { result, calls } = await runLoop({
    scope: loopScope({ testClasses: ["A06"] }),
    transport: new FakePlannerTransport([plan]),
    approval: approval.provider,
  });

  assert.equal(approval.requests.length, 1);
  assert.equal(result.stopReason, "planner_halt");
  assert.ok(!result.findings.some((finding) => /upload/i.test(finding.title)));
  assert.ok(!calls.some((call) => call.method === "POST"));
});

test("every reported finding has evidence and reproduction steps", async () => {
  const page =
    '<html><body><a href="/search?q=1">search</a></body></html>';
  const { result } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    modelEnabled: false,
    maxDepth: 1,
    maxUrls: 5,
    maxInputsPerCheck: 2,
    fetchHandler: async (url) => {
      if (url.includes("/search") && (url.includes("%27") || url.includes("'"))) {
        return new Response("You have an error in your SQL syntax", { status: 500 });
      }
      return new Response(page, {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    },
  });

  assert.ok(result.findings.length > 0);
  for (const finding of result.findings) {
    assert.ok(finding.evidence.length > 0, `${finding.title} has no evidence`);
    assert.ok(finding.reproduction.length > 0, `${finding.title} has no reproduction steps`);
  }
  assert.ok(
    result.findings.some(
      (finding) => finding.category === "A05" && /sql/i.test(finding.title),
    ),
    "expected a SQL injection finding",
  );
});

test("writes all report formats after verifying candidates", async () => {
  const page = '<html><body><a href="/search?q=1">search</a></body></html>';
  const { result, dir } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    modelEnabled: false,
    maxDepth: 1,
    maxUrls: 5,
    maxInputsPerCheck: 2,
    fetchHandler: async (url) => {
      if (url.includes("/search") && (url.includes("%27") || url.includes("'"))) {
        return new Response("You have an error in your SQL syntax", { status: 500 });
      }
      return new Response(page, { status: 200, headers: { "content-type": "text/html" } });
    },
  });

  assert.equal(result.reportDir, join(dir, "loop-test"));
  const files = await readdir(result.reportDir);
  for (const name of ["report.json", "report.md", "report.sarif", "audit.log"]) {
    assert.ok(files.includes(name), `expected ${name} in the run directory`);
  }

  for (const finding of result.findings) {
    assert.notEqual(finding.status, "candidate");
    assert.ok(finding.verification !== undefined, `${finding.title} was not verified`);
  }
  assert.equal(result.report.audit.integrity, "ok");

  const markdown = await readFile(join(result.reportDir, "report.md"), "utf8");
  assert.match(markdown, /# Anbu Pentest Report/);
  assert.match(markdown, /## Methodology/);
  assert.match(markdown, /## Coverage/);
  assert.match(markdown, /## Budgets/);
  assert.match(markdown, /## Audit log/);
  assert.doesNotMatch(markdown, /Discarded candidate/);

  const sarif = JSON.parse(
    await readFile(join(result.reportDir, "report.sarif"), "utf8"),
  ) as { version: string; runs: Array<{ results: unknown[] }> };
  assert.equal(sarif.version, "2.1.0");
  assert.ok(Array.isArray(sarif.runs[0].results));
});

test("repeated planner failures disable the model and still produce a report", async () => {
  const { result, dir, transport } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    transport: new FakePlannerTransport(["not json", "still not json"]),
  });

  assert.equal(result.modelAvailable, false);
  assert.equal(result.stopReason, "completed");
  assert.equal(transport.requests.length, 2);

  const audit = await readAuditLines(dir, "loop-test");
  assert.ok(audit.some((entry) => entry.event === "planner.disabled"));
});

test("a failing planner transport falls back to deterministic checks", async () => {
  const transport = new FakePlannerTransport([]);
  transport.startError = new Error("ollama unreachable");
  const { result, calls, dir } = await runLoop({
    scope: loopScope({ testClasses: ["A05"] }),
    transport,
  });

  assert.equal(transport.started, false);
  assert.equal(result.modelAvailable, false);
  assert.equal(result.stopReason, "completed");
  assert.ok(calls.length > 0);

  const audit = await readAuditLines(dir, "loop-test");
  assert.ok(audit.some((entry) => entry.event === "planner.unavailable"));
});

test("planner prompts never contain target credentials", async () => {
  const { transport } = await runLoop({
    scope: loopScope({
      testClasses: ["A05"],
      targets: [
        {
          host: "example.test",
          scheme: "https",
          port: 443,
          paths: ["/?token=super-secret"],
          methods: ["GET"],
        },
      ],
    }),
    transport: new FakePlannerTransport([haltPlan]),
  });

  assert.equal(transport.requests.length, 1);
  assert.ok(!transport.requests[0].user.includes("super-secret"));
  assert.match(transport.requests[0].user, /redacted/i);
});
