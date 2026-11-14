import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { reportCommand } from "../../../src/report.js";
import { makeReport } from "./helpers.js";

async function writeRunReport(report = makeReport()): Promise<{ dir: string; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-report-cmd-"));
  const file = join(dir, "report.json");
  await writeFile(file, JSON.stringify(report), "utf8");
  return { dir, file };
}

test("reportCommand renders a run directory report to a file", async () => {
  const { dir } = await writeRunReport();
  const out = join(dir, "report.md");

  await reportCommand(["--run", dir, "--out", out]);

  const markdown = await readFile(out, "utf8");
  assert.match(markdown, /# Anbu Pentest Report/);
});

test("reportCommand accepts a direct report.json path and other formats", async () => {
  const { file } = await writeRunReport();
  const out = join(dirname(file), "report.sarif");

  await reportCommand(["--run", file, "--format", "sarif", "--out", out]);

  const sarif = JSON.parse(await readFile(out, "utf8")) as { version: string };
  assert.equal(sarif.version, "2.1.0");
});

test("reportCommand includes discarded findings only with --all", async () => {
  const { dir } = await writeRunReport();
  const filtered = join(dir, "filtered.md");
  const all = join(dir, "all.md");

  await reportCommand(["--run", dir, "--out", filtered]);
  await reportCommand(["--run", dir, "--all", "--out", all]);

  assert.doesNotMatch(await readFile(filtered, "utf8"), /Discarded candidate/);
  assert.match(await readFile(all, "utf8"), /Discarded candidate/);
});

test("reportCommand refuses a file that is not an Anbu report", async () => {
  const dir = await mkdtemp(join(tmpdir(), "anbu-report-bad-"));
  await writeFile(join(dir, "report.json"), JSON.stringify({ hello: "world" }), "utf8");

  await assert.rejects(() => reportCommand(["--run", dir]), /not an Anbu report/);
});

test("reportCommand refuses an unknown format", async () => {
  const { dir } = await writeRunReport();
  await assert.rejects(
    () => reportCommand(["--run", dir, "--format", "xml"]),
    /unknown report format/,
  );
});
