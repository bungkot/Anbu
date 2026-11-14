import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { OWASP_CATEGORIES } from "../../../src/model/scope.js";
import {
  CHECKS,
  approvalRequiredChecks,
  checksForCategory,
  getCheck,
  getCheckByToolName,
  listChecks,
  readOnlyChecks,
  validateCheckRegistry,
} from "../../../src/tools/checks/index.js";

interface DocumentedCheck {
  toolName: string;
  id: string;
  categories: string;
  cwe: string;
  gate: string;
}

/** Parse the deterministic-check table out of docs/tool-reference.md. */
function documentedChecks(): DocumentedCheck[] {
  const doc = readFileSync(new URL("../../../docs/tool-reference.md", import.meta.url), "utf8");
  const checks: DocumentedCheck[] = [];
  for (const line of doc.split(/\r?\n/)) {
    if (!line.startsWith("| `check_")) continue;
    const cells = line.split("|").map((cell) => cell.trim());
    const toolName = cells[1]?.replace(/`/g, "") ?? "";
    const id = cells[2]?.replace(/`/g, "") ?? "";
    const categories = cells[3] ?? "";
    const cwe = cells[4]?.replace(/`/g, "") ?? "";
    const gate = cells[5]?.replace(/`/g, "") ?? "";
    if (toolName.length > 0 && id.length > 0) {
      checks.push({ toolName, id, categories, cwe, gate });
    }
  }
  return checks;
}

test("registry satisfies its invariants", () => {
  assert.deepEqual(validateCheckRegistry(), []);
});

test("registry matches the deterministic tools in docs/tool-reference.md", () => {
  const documented = documentedChecks();
  assert.ok(documented.length > 0, "no checks found in docs/tool-reference.md");
  const registry = new Map(CHECKS.map((check) => [check.metadata.id, check] as const));
  assert.equal(documented.length, registry.size);
  for (const entry of documented) {
    const check = registry.get(entry.id);
    assert.ok(check !== undefined, `docs entry ${entry.toolName} has unknown id ${entry.id}`);
    assert.equal(check.metadata.toolName, entry.toolName, `docs entry ${entry.id} tool name`);
    assert.equal(
      check.metadata.categories.join("/"),
      entry.categories,
      `docs entry ${entry.id} categories`,
    );
    assert.equal(check.metadata.cwe ?? "", entry.cwe, `docs entry ${entry.id} CWE`);
    assert.equal(
      check.metadata.readOnly ? "read-only" : "approval",
      entry.gate,
      `docs entry ${entry.id} approval gate`,
    );
  }
  const documentedIds = new Set(documented.map((entry) => entry.id));
  for (const check of CHECKS) {
    assert.ok(
      documentedIds.has(check.metadata.id),
      `registered check ${check.metadata.id} is missing from docs/tool-reference.md`,
    );
  }
});

test("registry exposes metadata for every check", () => {
  const metadata = listChecks();
  assert.equal(metadata.length, CHECKS.length);
  for (const item of metadata) {
    assert.ok(item.id.length > 0);
    assert.ok(item.toolName.startsWith("check_"));
    assert.ok(item.categories.length > 0);
    assert.ok(item.maxRequests >= 0);
    assert.ok(item.references.length > 0);
  }
});

test("every OWASP Top 10:2025 category has at least one check", () => {
  for (const category of OWASP_CATEGORIES) {
    assert.ok(checksForCategory(category).length > 0, `no deterministic check covers ${category}`);
  }
});

test("state-changing checks require approval and read-only checks do not", () => {
  for (const check of CHECKS) {
    if (check.metadata.readOnly) {
      assert.equal(check.metadata.requiresApproval, false, check.metadata.id);
    } else {
      assert.equal(check.metadata.requiresApproval, true, check.metadata.id);
    }
  }
  assert.ok(approvalRequiredChecks().length > 0);
  assert.ok(readOnlyChecks().length > 0);
});

test("lookups by id and tool name are stable", () => {
  assert.equal(getCheck("sqli")?.metadata.toolName, "check_sqli");
  assert.equal(getCheckByToolName("check_xss")?.metadata.id, "xss");
  assert.equal(getCheck("not-a-check"), undefined);
  assert.equal(getCheckByToolName("check_not_a_tool"), undefined);
});
