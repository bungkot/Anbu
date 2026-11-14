/**
 * Metrics helper for the staged Ollama CI workflow.
 *
 * Usage:
 *   node scripts/ci-metrics.mjs benchmark <ollama-response.json> <out.json> <wall-ms>
 *   node scripts/ci-metrics.mjs timing <out.json> <wall-ms>
 *   node scripts/ci-metrics.mjs summary <metrics-dir>
 *   node scripts/ci-metrics.mjs result <pentest-report.json>
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readTiming(dir, name) {
  try {
    return readJson(join(dir, name));
  } catch {
    return undefined;
  }
}

function round(value, digits = 2) {
  return Number(Number(value).toFixed(digits));
}

function rate(count, durationNs) {
  if (!Number.isFinite(count) || !Number.isFinite(durationNs) || durationNs <= 0) return 0;
  return round(count / (durationNs / 1e9));
}

function benchmark([responsePath, outPath, wallMs]) {
  if (responsePath === undefined || outPath === undefined || wallMs === undefined) {
    throw new Error("benchmark requires <response.json> <out.json> <wall-ms>");
  }
  const response = readJson(responsePath);
  const metrics = {
    wallSeconds: round(Number(wallMs) / 1000),
    loadSeconds: round((response.load_duration ?? 0) / 1e9),
    promptTokens: response.prompt_eval_count ?? 0,
    promptTokensPerSecond: rate(
      response.prompt_eval_count ?? 0,
      response.prompt_eval_duration ?? 0,
    ),
    generatedTokens: response.eval_count ?? 0,
    generationTokensPerSecond: rate(response.eval_count ?? 0, response.eval_duration ?? 0),
    totalSeconds: round((response.total_duration ?? 0) / 1e9),
  };
  writeFileSync(outPath, `${JSON.stringify(metrics, null, 2)}\n`);
}

function timing([outPath, wallMs]) {
  if (outPath === undefined || wallMs === undefined) {
    throw new Error("timing requires <out.json> <wall-ms>");
  }
  writeFileSync(outPath, `${JSON.stringify({ seconds: round(Number(wallMs) / 1000) }, null, 2)}\n`);
}

function result([reportPath]) {
  if (reportPath === undefined) throw new Error("result requires <pentest-report.json>");
  let report;
  try {
    report = readJson(reportPath);
  } catch {
    console.log(
      "No pentest report was produced; the stage failed or timed out before writing one.",
    );
    return;
  }
  const budgets = report.budgets ?? {};
  const findings = report.summary ?? {};
  console.log(`Model-assisted : ${report.methodology?.modelAssisted === true}`);
  console.log(`Stop reason    : ${report.stopReason ?? "unknown"}`);
  console.log(`Model turns    : ${budgets.usedModelTurns ?? "?"}/${budgets.maxModelTurns ?? "?"}`);
  console.log(`Requests       : ${budgets.usedRequests ?? "?"}/${budgets.maxRequests ?? "?"}`);
  console.log(
    `Findings       : ${findings.reported ?? 0} reported, ${findings.discarded ?? 0} withheld`,
  );
}

function number(value) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(2) : "n/a";
}

function outcome(value) {
  return value === undefined || value.length === 0 ? "not run" : value;
}

function benchmarkCell(metrics) {
  if (metrics === undefined) return "n/a";
  return [
    `load ${number(metrics.loadSeconds)} s`,
    `prompt ${number(metrics.promptTokensPerSecond)} tok/s`,
    `generation ${number(metrics.generationTokensPerSecond)} tok/s`,
    `${metrics.generatedTokens} tokens`,
    `total ${number(metrics.totalSeconds)} s`,
  ].join(", ");
}

function askCell(metrics) {
  return metrics === undefined ? "n/a" : `${number(metrics.seconds)} s end-to-end`;
}

function pentestCell(report, timingMetrics) {
  if (report === undefined) return "n/a";
  const budgets = report.budgets ?? {};
  const findings = report.summary ?? {};
  const parts = [];
  if (timingMetrics !== undefined) parts.push(`${number(timingMetrics.seconds)} s`);
  parts.push(`${budgets.usedRequests ?? "?"}/${budgets.maxRequests ?? "?"} requests`);
  parts.push(`${budgets.usedModelTurns ?? "?"}/${budgets.maxModelTurns ?? "?"} model turns`);
  parts.push(String(report.stopReason ?? "unknown"));
  parts.push(report.methodology?.modelAssisted === true ? "model-assisted" : "deterministic only");
  if (typeof findings.reported === "number") {
    parts.push(`${findings.reported} reported / ${findings.discarded ?? 0} withheld`);
  }
  return parts.join(", ");
}

function summary([dir]) {
  if (dir === undefined) throw new Error("summary requires <metrics-dir>");
  const bench = readTiming(dir, "benchmark.json");
  const ask = readTiming(dir, "ask.json");
  const deterministic = readTiming(dir, "deterministic-pentest.json");
  const deterministicTime = readTiming(dir, "deterministic-seconds.json");
  const model = readTiming(dir, "model-pentest.json");
  const modelTime = readTiming(dir, "model-seconds.json");
  const stage = process.env.STAGE ?? "model";

  console.log("## Ollama staged CI");
  console.log("");
  console.log(
    `Stage selection: \`${stage}\` | model: \`${process.env.OLLAMA_MODEL ?? "unknown"}\``,
  );
  console.log("");
  console.log("| Stage | Result | Metrics |");
  console.log("| --- | --- | --- |");
  console.log(
    `| 1. Ollama benchmark | ${outcome(process.env.BENCHMARK_OUTCOME)} | ${benchmarkCell(bench)} |`,
  );
  console.log(`| 1. OpenCode ask | ${outcome(process.env.ASK_OUTCOME)} | ${askCell(ask)} |`);
  console.log(
    `| 2. Deterministic pentest | ${outcome(process.env.DETERMINISTIC_OUTCOME)} | ` +
      `${pentestCell(deterministic, deterministicTime)} |`,
  );
  console.log(
    `| 3. Model-guided pentest | ${outcome(process.env.MODEL_OUTCOME)} | ` +
      `${pentestCell(model, modelTime)} |`,
  );
  console.log("");
  if (stage === "model") {
    console.log(
      "Stage 3 is experimental and non-blocking: a CPU-only runner can exceed the SDK planner " +
        "timeout. A failure is recorded here and in the step outcome, but does not fail the workflow.",
    );
  }
}

const [command, ...args] = process.argv.slice(2);
try {
  if (command === "benchmark") benchmark(args);
  else if (command === "timing") timing(args);
  else if (command === "summary") summary(args);
  else if (command === "result") result(args);
  else throw new Error("expected one of: benchmark | timing | summary | result");
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
