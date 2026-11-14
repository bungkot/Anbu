import { test } from "node:test";
import assert from "node:assert/strict";
import {
  autoApprove,
  denyAllApprovals,
  interactiveApprovals,
  isApprovedAnswer,
} from "../../../src/agent/approval.js";
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

test("autoApprove grants every request without inspecting it", async () => {
  const decisions = await Promise.all([
    autoApprove.approve(request),
    autoApprove.approve({ ...request, action: "verify:upload" }),
    autoApprove.approve({
      ...request,
      action: "run_check:rate-limit",
      url: "https://other.example/",
    }),
  ]);
  assert.deepEqual(decisions, [true, true, true]);
});

test("interactiveApprovals forwards the request to the operator decision", async () => {
  const seen: ApprovalRequest[] = [];
  const provider = interactiveApprovals({
    ask: async (approvalRequest) => {
      seen.push(approvalRequest);
      return true;
    },
  });

  assert.equal(await provider.approve(request), true);
  assert.deepEqual(seen, [request]);
});

test("interactiveApprovals supports synchronous and negative decisions", async () => {
  const no = interactiveApprovals({ ask: () => false });
  const yes = interactiveApprovals({ ask: () => true });
  assert.equal(await no.approve(request), false);
  assert.equal(await yes.approve(request), true);
});

test("isApprovedAnswer accepts only an explicit affirmative", () => {
  assert.equal(isApprovedAnswer("y"), true);
  assert.equal(isApprovedAnswer(" yes "), true);
  assert.equal(isApprovedAnswer("YES"), true);
  assert.equal(isApprovedAnswer("n"), false);
  assert.equal(isApprovedAnswer(""), false);
  assert.equal(isApprovedAnswer("yes please"), false);
  assert.equal(isApprovedAnswer("true"), false);
});
