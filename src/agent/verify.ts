import type { AuditLog } from "../audit/log.js";
import type { Finding, FindingVerification } from "../model/finding.js";
import type { Scope } from "../model/scope.js";
import type { EvidenceStore } from "../store/evidence-store.js";
import { createCheckContext } from "../tools/checks/context.js";
import { getCheck } from "../tools/checks/index.js";
import type { CheckInput, CheckResult } from "../tools/checks/types.js";
import type { GuardedHttpClient } from "../tools/http.js";
import type { ApprovalProvider } from "./approval.js";
import { denyAllApprovals } from "./approval.js";

export interface VerifyOptions {
  findings: Finding[];
  scope: Scope;
  store: EvidenceStore;
  client: GuardedHttpClient;
  audit: AuditLog;
  approval?: ApprovalProvider;
  now?: () => Date;
  /** Maximum number of check re-runs. Default 25. */
  maxReproductions?: number;
  /** Per-reproduction request cap. Defaults to the check's own maxRequests. */
  maxRequestsPerReproduction?: number;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function safeTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

/** Findings from the same check and input are reproduced together. */
function reproductionKey(finding: Finding): string {
  return `${finding.checkId ?? ""}\u0000${finding.affected.url}\u0000${finding.affected.parameter ?? ""}`;
}

/** A reproduced finding matches the candidate on category, title, and target. */
function findingMatchKey(finding: Finding): string {
  return `${finding.category}\u0000${finding.title}\u0000${finding.affected.url}\u0000${finding.affected.parameter ?? ""}`;
}

function setVerification(finding: Finding, verification: FindingVerification): void {
  finding.verification = verification;
  if (verification.status === "confirmed") {
    finding.status = "confirmed";
    finding.confidence = "confirmed";
  } else if (verification.status === "probable") {
    finding.status = "probable";
    finding.confidence = "probable";
  } else {
    finding.status = "discarded";
    finding.confidence = "unverified";
  }
}

/**
 * Rebuild a closed check input from the finding. The sanitized check input is
 * preferred because it retains options (alternate ids, candidate paths, and so
 * on) that the captured request does not contain. Findings without a stored
 * input fall back to their captured request; redacted bodies are dropped rather
 * than replayed. Headers are intentionally not replayed: captured headers are
 * sanitized, and checks authenticate through the guarded client, not through
 * stored credentials.
 */
function rebuildInput(finding: Finding, method: string, body: string | undefined): CheckInput {
  const stored = finding.checkInput;
  if (stored !== undefined) {
    const input: CheckInput = { url: finding.affected.url };
    if (stored.method !== undefined && stored.method !== "GET") input.method = stored.method;
    if (stored.parameter !== undefined) input.parameter = stored.parameter;
    if (stored.body !== undefined) input.body = stored.body;
    if (stored.options !== undefined) input.options = stored.options;
    return input;
  }

  const input: CheckInput = { url: finding.affected.url };
  if (finding.affected.parameter !== undefined) input.parameter = finding.affected.parameter;
  const normalized = method.toUpperCase();
  if (normalized.length > 0 && normalized !== "GET") input.method = normalized;
  if (body !== undefined && !body.includes("[REDACTED]")) input.body = body;
  return input;
}

async function auditFinding(
  audit: AuditLog,
  event: string,
  finding: Finding,
  reason: string,
): Promise<void> {
  await audit.append(event, {
    category: finding.category,
    target: safeTarget(finding.affected.url),
    reason,
  });
}

/**
 * Verify state: reproduce every candidate finding by re-running its originating
 * check through the same guarded tool layer. Findings that cannot be reproduced
 * are discarded; findings that cannot be attempted safely stay probable and are
 * reported with their verification reason.
 */
export async function verifyFindings(options: VerifyOptions): Promise<Finding[]> {
  const now = options.now ?? (() => new Date());
  const approval = options.approval ?? denyAllApprovals;
  const maxReproductions = options.maxReproductions ?? 25;
  const findings = options.findings;

  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (finding.status === "discarded") continue;
    if (finding.checkId === undefined || finding.checkId.length === 0) {
      setVerification(finding, {
        status: "probable",
        reason: "no originating check is recorded, so the finding cannot be reproduced",
        attempted: false,
      });
      await auditFinding(options.audit, "verify.skipped", finding, "no originating check");
      continue;
    }
    const key = reproductionKey(finding);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [finding]);
    else group.push(finding);
  }

  let reproductions = 0;
  for (const group of groups.values()) {
    const first = group[0];
    const checkId = first.checkId;
    if (checkId === undefined) continue;

    if (reproductions >= maxReproductions) {
      const reason = `verification budget reached (${maxReproductions} reproductions)`;
      for (const finding of group) {
        setVerification(finding, { status: "probable", reason, attempted: false });
      }
      await auditFinding(options.audit, "verify.skipped", first, reason);
      continue;
    }
    reproductions += 1;

    const check = getCheck(checkId);
    if (check === undefined) {
      const reason = `unknown originating check: ${checkId}`;
      for (const finding of group) {
        setVerification(finding, { status: "probable", reason, attempted: false });
      }
      await auditFinding(options.audit, "verify.skipped", first, reason);
      continue;
    }

    const ref = first.evidence[0];
    const artifact = ref === undefined ? undefined : await options.store.get(ref.evidenceId);
    if (ref === undefined || artifact === undefined || artifact.sha256 !== ref.sha256) {
      const reason = "evidence is missing or failed integrity verification";
      for (const finding of group) {
        setVerification(finding, { status: "discarded", reason, attempted: false });
      }
      await auditFinding(options.audit, "verify.discarded", first, reason);
      continue;
    }

    if (first.checkInput?.redacted === true) {
      const reason =
        "the stored check input was redacted, so the finding cannot be reproduced faithfully";
      for (const finding of group) {
        setVerification(finding, { status: "probable", reason, attempted: false });
      }
      await auditFinding(options.audit, "verify.skipped", first, reason);
      continue;
    }

    if (!check.metadata.readOnly || check.metadata.requiresApproval) {
      const approved = await approval.approve({
        action: `verify:${check.metadata.id}`,
        method: "GET",
        url: first.affected.url,
        reason: "reproducing a state-changing finding requires approval",
      });
      await options.audit.append(approved ? "approval.granted" : "approval.denied", {
        check: check.metadata.id,
        target: safeTarget(first.affected.url),
      });
      if (!approved) {
        const reason = "state-changing reproduction was not approved";
        for (const finding of group) {
          setVerification(finding, { status: "probable", reason, attempted: false });
        }
        await auditFinding(options.audit, "verify.skipped", first, reason);
        continue;
      }
    }

    const input = rebuildInput(first, artifact.request.method, artifact.request.body);
    const checkCtx = createCheckContext({
      scope: options.scope,
      client: options.client,
      store: options.store,
      audit: options.audit,
      now,
      maxRequests: options.maxRequestsPerReproduction ?? check.metadata.maxRequests,
    });

    let result: CheckResult;
    try {
      result = await check.run(checkCtx, input);
    } catch (err) {
      const reason = `reproduction failed: ${errorMessage(err)}`;
      for (const finding of group) {
        setVerification(finding, { status: "probable", reason, attempted: true });
      }
      await auditFinding(options.audit, "verify.error", first, reason);
      continue;
    }

    const produced = new Map<string, Finding>();
    for (const candidate of result.findings) produced.set(findingMatchKey(candidate), candidate);

    for (const finding of group) {
      const match = produced.get(findingMatchKey(finding));
      if (match === undefined) {
        const reason = "the originating check did not reproduce the finding on re-run";
        setVerification(finding, { status: "discarded", reason, attempted: true });
        await auditFinding(options.audit, "verify.discarded", finding, reason);
        continue;
      }

      const evidenceId = match.evidence[0]?.evidenceId;
      let reason = "the originating check reproduced the finding";
      if (evidenceId !== undefined) {
        const comparison = await options.store.compare(evidenceId, ref.evidenceId);
        if (comparison.ok) {
          reason += comparison.comparison.body.changed
            ? "; the reproduced response body differs from the captured baseline"
            : "; the reproduced response matches the captured baseline";
        }
      }
      setVerification(finding, { status: "confirmed", reason, attempted: true, evidenceId });
      await auditFinding(options.audit, "verify.confirmed", finding, reason);
    }
  }

  return findings;
}
