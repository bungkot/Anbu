/**
 * Deterministic agent-loop simulation for the dev container.
 *
 * Starts the local vulnerable fixture, writes an authorized read-only scope,
 * and runs the real bounded loop with a scripted planner transport. No model or
 * external network is required. Pass --live to use the OpenCode/Ollama planner
 * instead of the scripted one.
 *
 * Usage: npm run sim:agent [-- --live]
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { runPentest } from "../src/agent/loop.js";
import type { PlannerTextResult, PlannerTransport } from "../src/agent/planner.js";
import type { Scope } from "../src/model/scope.js";
import { isReported } from "../src/report/index.js";
import { startTargetFixture } from "../test/target/fixture.js";

const OUT_ROOT = resolve("workspace/agent-loop-sim");
const live = process.argv.includes("--live");

type SimAction =
  | {
      kind: "run_check";
      checkId: string;
      input: {
        url: string;
        parameter?: string;
        options?: Record<string, unknown>;
      };
    }
  | { kind: "http_request"; input: { method: string; url: string } }
  | { kind: "halt"; reason: string };

interface SimPlan {
  objective: string;
  rationale?: string;
  actions: SimAction[];
}

function describeAction(action: SimAction): string {
  switch (action.kind) {
    case "run_check": {
      const parameter =
        action.input.parameter === undefined ? "" : ` parameter=${action.input.parameter}`;
      const options =
        action.input.options === undefined
          ? ""
          : ` options=${JSON.stringify(action.input.options)}`;
      return `run_check ${action.checkId} ${action.input.url}${parameter}${options}`;
    }
    case "http_request":
      return `http_request ${action.input.method} ${action.input.url}`;
    case "halt":
      return `halt (${action.reason})`;
  }
}

class ScriptedPlannerTransport implements PlannerTransport {
  private index = 0;

  constructor(private readonly plans: SimPlan[]) {}

  async start(): Promise<void> {}

  async stop(): Promise<void> {}

  async request(): Promise<PlannerTextResult> {
    const plan = this.plans[this.index];
    this.index += 1;
    if (plan === undefined) {
      return { ok: false, error: "simulation script exhausted" };
    }
    console.log(`\n[planner] turn ${this.index}: ${plan.objective}`);
    if (plan.rationale !== undefined) console.log(`  rationale: ${plan.rationale}`);
    for (const action of plan.actions) {
      console.log(`  action: ${describeAction(action)}`);
    }
    return { ok: true, text: JSON.stringify(plan) };
  }
}

function simulationPlans(baseUrl: string): SimPlan[] {
  return [
    {
      objective: "Confirm reflected input handling on the search endpoint",
      rationale: "Recon discovered /search?q=; probe it directly instead of only the root.",
      actions: [
        {
          kind: "run_check",
          checkId: "xss",
          input: { url: `${baseUrl}/search?q=simulation`, parameter: "q" },
        },
        {
          kind: "run_check",
          checkId: "sqli",
          input: { url: `${baseUrl}/search?q=simulation`, parameter: "q" },
        },
      ],
    },
    {
      objective: "Probe access control, API CORS, and both human-in-the-loop gates",
      rationale:
        "Target discovered API/admin endpoints, then deliberately include one out-of-scope " +
        "request and one state-changing check so the guardrail and approval paths are exercised.",
      actions: [
        {
          kind: "run_check",
          checkId: "cors",
          input: { url: `${baseUrl}/api/data` },
        },
        {
          kind: "run_check",
          checkId: "force-browsing",
          input: { url: baseUrl, options: { paths: ["/admin"] } },
        },
        {
          kind: "http_request",
          input: { method: "GET", url: `${baseUrl}/audit` },
        },
        {
          kind: "http_request",
          input: { method: "GET", url: "https://out-of-scope.invalid/" },
        },
        {
          kind: "run_check",
          checkId: "upload",
          input: { url: `${baseUrl}/login` },
        },
      ],
    },
    {
      objective: "Finish the simulation",
      actions: [{ kind: "halt", reason: "scripted simulation complete" }],
    },
  ];
}

function printCoverage(result: Awaited<ReturnType<typeof runPentest>>): void {
  console.log("\nCoverage:");
  for (const entry of result.coverage) {
    console.log(
      `  ${entry.category}: ${entry.status} (${entry.findings} findings, ${entry.checks} checks)`,
    );
  }
}

function printFindings(result: Awaited<ReturnType<typeof runPentest>>): void {
  const reported = result.findings.filter(isReported);
  const withheld = result.findings.length - reported.length;
  console.log(`\nFindings (${reported.length} reported, ${withheld} withheld):`);
  for (const finding of reported) {
    const parameter =
      finding.affected.parameter === undefined ? "" : `?${finding.affected.parameter}`;
    console.log(
      `  [${finding.severity}/${finding.confidence}] ${finding.category} ${finding.title} ` +
        `(${finding.affected.url}${parameter})`,
    );
  }
}

function printAuditDecisions(result: Awaited<ReturnType<typeof runPentest>>): void {
  const events = result.report.audit.events;
  const denies = events.filter((entry) => entry.event === "guardrail" && entry.decision === "deny");
  console.log(`\nGuardrail denies (${denies.length}):`);
  for (const entry of denies) {
    console.log(`  - ${entry.method ?? "?"} ${entry.target ?? "?"}: ${entry.reason ?? "denied"}`);
  }

  const approvals = events.filter((entry) => entry.event.startsWith("approval."));
  console.log(`Approval decisions (${approvals.length}):`);
  for (const entry of approvals) {
    console.log(`  - ${entry.event} ${entry.target ?? ""}`.trimEnd());
  }
}

async function main(): Promise<void> {
  const fixture = await startTargetFixture();
  const runId = `run-${new Date().toISOString().replace(/[:.]/g, "-")}`;

  try {
    const scope: Scope = {
      version: 1,
      name: "Agent-loop simulation: local vulnerable fixture",
      authorization: {
        reference: "SIMULATION-2026-001",
        owner: "Local lab operator",
        issuedBy: "Local lab operator",
        validFrom: "2020-01-01T00:00:00Z",
        validUntil: "2035-01-01T00:00:00Z",
        token: "env:ANBU_AUTH_TOKEN",
      },
      targets: [
        {
          host: "127.0.0.1",
          scheme: "http",
          port: fixture.port,
          paths: ["/"],
          methods: ["GET", "HEAD", "OPTIONS"],
        },
      ],
      deny: [],
      testClasses: ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
      readOnly: true,
      policy: {
        maxRequests: 300,
        // Live mode drives a real (possibly CPU-bound) Ollama model; one
        // planner turn can take several minutes, so allow a longer run than
        // the 5-minute scripted budget.
        maxDurationMinutes: live ? 30 : 5,
        maxModelTurns: 6,
        maxFindingsPerCategory: 25,
        maxBodyBytes: 65_536,
        maxRedirects: 3,
        followExternalRedirects: false,
        requestsPerSecondPerHost: 100,
      },
    };

    await mkdir(OUT_ROOT, { recursive: true });
    const scopePath = join(OUT_ROOT, "scope.json");
    await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");

    const planner = new ScriptedPlannerTransport(simulationPlans(fixture.baseUrl));

    console.log("Anbu agent-loop simulation");
    console.log(`  Target   : ${fixture.baseUrl}`);
    console.log(`  Scope    : ${scopePath}`);
    console.log(`  Planner  : ${live ? "live OpenCode/Ollama" : "scripted (deterministic)"}`);
    console.log("  Approval : deny-all (state-changing checks will be skipped)");
    console.log("\nRunning intake -> recon -> deterministic baseline -> planner loop -> verify...");

    const result = await runPentest({
      scopePath,
      runId,
      evidenceDir: OUT_ROOT,
      env: (name) => (name === "ANBU_AUTH_TOKEN" ? "simulation-token" : process.env[name]),
      modelEnabled: true,
      transport: live ? undefined : planner,
      maxDepth: 1,
      maxUrls: 20,
      maxInputsPerCheck: 1,
      maxReproductions: 25,
      approvalMode: "deny-all",
    });

    if (!result.ok) {
      console.error("\nSimulation refused to start:");
      for (const error of result.errors ?? []) console.error(`  - ${error}`);
      process.exitCode = 1;
      return;
    }

    console.log("\nResult:");
    console.log(`  Stop reason : ${result.stopReason}`);
    console.log(`  Model       : ${result.modelAvailable ? "available" : "unavailable"}`);
    console.log(
      `  Budgets     : requests ${result.budgets.usedRequests}/${result.budgets.maxRequests}, ` +
        `model turns ${result.budgets.usedModelTurns}/${result.budgets.maxModelTurns}, ` +
        `elapsed ${result.budgets.elapsedMinutes.toFixed(1)}/${result.budgets.maxDurationMinutes} min`,
    );
    console.log(
      `  Audit       : ${result.report.audit.integrity} (${result.report.audit.entries} entries)`,
    );

    printCoverage(result);
    printFindings(result);
    printAuditDecisions(result);

    console.log(`\nReports       : ${result.reportDir}`);
    console.log(`  report.json : ${join(result.reportDir, "report.json")}`);
    console.log(`  report.md   : ${join(result.reportDir, "report.md")}`);
    console.log(`  report.sarif: ${join(result.reportDir, "report.sarif")}`);
    console.log(`  audit.log   : ${join(result.reportDir, "audit.log")}`);
    if (result.llmBacklogPath !== undefined) {
      console.log(`  LLM backlog : ${result.llmBacklogPath}`);
    }
  } finally {
    await fixture.close();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
