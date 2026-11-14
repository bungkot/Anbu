import { test } from "node:test";
import assert from "node:assert/strict";
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

const EXPECTED_TOOL_NAMES = [
  "check_security_headers",
  "check_tls",
  "check_password_hash",
  "check_dependencies",
  "check_sqli",
  "check_xss",
  "check_command_injection",
  "check_xxe",
  "check_path_traversal",
  "check_idor",
  "check_force_browsing",
  "check_cors",
  "check_jwt",
  "check_authz_methods",
  "check_default_credentials",
  "check_error_handling",
  "check_logging",
  "check_deserialization",
  "check_upload",
  "check_rate_limit",
];

test("registry satisfies its invariants", () => {
  assert.deepEqual(validateCheckRegistry(), []);
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

test("registry covers every deterministic tool in docs/tool-reference.md", () => {
  const toolNames = CHECKS.map((check) => check.metadata.toolName).sort();
  assert.deepEqual(toolNames, [...EXPECTED_TOOL_NAMES].sort());
});

test("every OWASP Top 10:2025 category has at least one check", () => {
  for (const category of OWASP_CATEGORIES) {
    assert.ok(
      checksForCategory(category).length > 0,
      `no deterministic check covers ${category}`,
    );
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
