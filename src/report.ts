import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Report } from "./model/report.js";
import { renderJson, renderMarkdown, renderSarif } from "./report/index.js";

interface ReportArgs {
  /** Run directory or direct path to report.json. */
  runPath?: string;
  format: "markdown" | "json" | "sarif";
  out?: string;
  all: boolean;
}

function parseReportArgs(args: string[]): ReportArgs {
  const parsed: ReportArgs = { format: "markdown", all: false };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const value = args[i + 1];
    if (arg === "--run" && value !== undefined) {
      parsed.runPath = value;
      i += 1;
    } else if (arg.startsWith("--run=")) {
      parsed.runPath = arg.slice("--run=".length);
    } else if (arg === "--format" && value !== undefined) {
      if (value !== "markdown" && value !== "json" && value !== "sarif") {
        throw new Error(`unknown report format: ${value}`);
      }
      parsed.format = value;
      i += 1;
    } else if (arg.startsWith("--format=")) {
      const format = arg.slice("--format=".length);
      if (format !== "markdown" && format !== "json" && format !== "sarif") {
        throw new Error(`unknown report format: ${format}`);
      }
      parsed.format = format;
    } else if (arg === "--out" && value !== undefined) {
      parsed.out = value;
      i += 1;
    } else if (arg.startsWith("--out=")) {
      parsed.out = arg.slice("--out=".length);
    } else if (arg === "--all") {
      parsed.all = true;
    } else {
      throw new Error(`unknown report argument: ${arg}`);
    }
  }
  return parsed;
}

function resolveReportFile(runPath: string): string {
  return runPath.endsWith(".json") ? runPath : join(runPath, "report.json");
}

function isReport(value: unknown): value is Report {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.runId === "string" &&
    typeof record.scopeReference === "string" &&
    typeof record.generatedAt === "string" &&
    Array.isArray(record.findings) &&
    Array.isArray(record.coverage) &&
    typeof record.budgets === "object" &&
    record.budgets !== null &&
    typeof record.methodology === "object" &&
    record.methodology !== null &&
    typeof record.audit === "object" &&
    record.audit !== null
  );
}

/**
 * Render a run report that `pentest` already wrote to the evidence directory.
 * By default only confirmed and probable findings are included; `--all` embeds
 * discarded candidates too.
 */
export async function reportCommand(args: string[]): Promise<void> {
  const parsed = parseReportArgs(args);
  if (parsed.runPath === undefined) {
    throw new Error(
      "Usage: report --run <evidence-dir|report.json> [--format markdown|json|sarif] [--out <file>] [--all]",
    );
  }

  const reportFile = resolveReportFile(parsed.runPath);
  let raw: string;
  try {
    raw = await readFile(reportFile, "utf8");
  } catch (err) {
    throw new Error(
      `cannot read report file: ${(err as NodeJS.ErrnoException).code ?? "unknown error"}`,
      { cause: err },
    );
  }

  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("report file is not valid JSON");
  }
  if (!isReport(value)) {
    throw new Error("report file is not an Anbu report");
  }

  const report: Report = value;
  const rendered =
    parsed.format === "sarif"
      ? renderSarif(report, { includeDiscarded: parsed.all })
      : parsed.format === "json"
        ? renderJson(report, { includeDiscarded: parsed.all })
        : renderMarkdown(report, { includeDiscarded: parsed.all });

  if (parsed.out !== undefined) {
    await writeFile(parsed.out, rendered, "utf8");
    console.log(`Report written to ${parsed.out}`);
    return;
  }
  console.log(rendered);
}
