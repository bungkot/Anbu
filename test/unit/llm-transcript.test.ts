import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LlmTranscript } from "../../src/audit/llm-transcript.js";

async function tempTranscript(): Promise<LlmTranscript> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-llm-"));
  return new LlmTranscript({
    dir,
    runId: "run-1",
    provider: "ollama",
    model: "granite3.3:2b",
  });
}

test("records a request/response pair as JSONL and Markdown", async () => {
  const transcript = await tempTranscript();
  await transcript.record({
    agent: "planner",
    purpose: "planner.plan",
    turn: 1,
    agentPrompt: "Return JSON only.",
    system: "You are the planner.",
    user: "Find injection issues.",
    startedAt: Date.parse("2026-01-01T00:00:00Z"),
    durationMs: 42,
    ok: true,
    response: '{"actions":[]}',
  });

  const jsonl = await readFile(transcript.jsonlPath, "utf8");
  const lines = jsonl.trim().split("\n");
  assert.equal(lines.length, 1);
  const exchange = JSON.parse(lines[0]) as Record<string, unknown>;
  assert.equal(exchange.runId, "run-1");
  assert.equal(exchange.agent, "planner");
  assert.equal(exchange.turn, 1);
  assert.equal(exchange.durationMs, 42);
  assert.equal(exchange.ok, true);
  assert.equal(exchange.response, '{"actions":[]}');

  const markdown = await readFile(transcript.markdownPath, "utf8");
  assert.match(markdown, /# LLM backlog/);
  assert.match(markdown, /## \[1\] planner · planner\.plan/);
  assert.match(markdown, /Find injection issues\./);
  assert.match(markdown, /\{"actions":\[\]\}/);
});

test("records errors and redacts credentials", async () => {
  const transcript = await tempTranscript();
  await transcript.record({
    agent: "ask",
    purpose: "ask.prompt",
    turn: 1,
    user: "password=supersecret&token=abc123",
    startedAt: Date.now(),
    durationMs: 5,
    ok: false,
    error: "planner prompt failed: unauthorized",
  });

  const jsonl = await readFile(transcript.jsonlPath, "utf8");
  assert.doesNotMatch(jsonl, /supersecret/);
  assert.doesNotMatch(jsonl, /abc123/);
  assert.match(jsonl, /\[REDACTED\]/);
  assert.match(jsonl, /planner prompt failed/);
});

test("appends multiple turns without duplicating the header", async () => {
  const transcript = await tempTranscript();
  for (let turn = 1; turn <= 2; turn++) {
    await transcript.record({
      agent: "planner",
      purpose: "planner.plan",
      turn,
      user: `turn ${turn}`,
      startedAt: Date.now(),
      durationMs: 1,
      ok: true,
      response: "ok",
    });
  }

  const markdown = await readFile(transcript.markdownPath, "utf8");
  assert.equal(markdown.match(/# LLM backlog/g)?.length, 1);
  assert.match(markdown, /## \[1\]/);
  assert.match(markdown, /## \[2\]/);

  const jsonl = await readFile(transcript.jsonlPath, "utf8");
  assert.equal(jsonl.trim().split("\n").length, 2);
});
