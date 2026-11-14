import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/audit/log.js";

async function tempLog(): Promise<{ path: string; log: AuditLog }> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-audit-"));
  const path = join(dir, "audit.log");
  return { path, log: new AuditLog(path, "run-1") };
}

test("audit entries form a hash chain", async () => {
  const { log } = await tempLog();
  const first = await log.append("request", {
    decision: "allow",
    method: "GET",
    target: "https://example.test/",
  });
  const second = await log.append("request", { decision: "deny", reason: "out of scope" });
  assert.equal(first.seq, 1);
  assert.equal(second.seq, 2);
  assert.equal(second.prevHash, first.hash);

  const verify = await log.verify();
  assert.equal(verify.ok, true);
  assert.equal(verify.entries, 2);
});

test("audit log chains across instances", async () => {
  const { path } = await tempLog();
  const first = new AuditLog(path, "run-1");
  await first.append("request");
  const second = new AuditLog(path, "run-1");
  const entry = await second.append("request");
  assert.equal(entry.seq, 2);

  const verify = await second.verify();
  assert.equal(verify.ok, true);
});

test("audit log detects tampering", async () => {
  const { path } = await tempLog();
  const log = new AuditLog(path, "run-1");
  await log.append("request", { decision: "allow" });
  await log.append("request", { decision: "deny" });

  const text = await readFile(path, "utf8");
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  const first = JSON.parse(lines[0]) as Record<string, unknown>;
  first.event = "tampered";
  lines[0] = JSON.stringify(first);
  await writeFile(path, `${lines.join("\n")}\n`, "utf8");

  const reloaded = new AuditLog(path, "run-1");
  const verify = await reloaded.verify();
  assert.equal(verify.ok, false);
  assert.equal(verify.brokenAt, 1);
});
