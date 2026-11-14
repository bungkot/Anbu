import { test } from "node:test";
import assert from "node:assert/strict";
import { denyAllApprovals } from "../../../src/agent/approval.js";
import type { ApprovalRequest } from "../../../src/agent/approval.js";

const request: ApprovalRequest = {
  action: "run_check:upload",
  method: "POST",
  url: "https://example.test/upload",
  reason: "check is state-changing and requires approval",
};

test("denyAllApprovals rejects every state-changing action", async () => {
  assert.equal(await denyAllApprovals.approve(request), false);
});

test("denyAllApprovals does not depend on the request contents", async () => {
  const decisions = await Promise.all([
    denyAllApprovals.approve(request),
    denyAllApprovals.approve({ ...request, action: "run_check:default-credentials" }),
    denyAllApprovals.approve({ ...request, action: "run_check:authz-methods" }),
  ]);
  assert.deepEqual(decisions, [false, false, false]);
});
