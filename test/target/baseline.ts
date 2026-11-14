import { readFile } from "node:fs/promises";
import type { Report } from "../../src/model/report.js";
import { isReported } from "../../src/report/index.js";

export interface IgnoredBaselineCheck {
  checkId: string;
  reason: string;
}

/**
 * Expected findings for one known-vulnerable fixture. A baseline records the
 * deterministic check ids that must be reported, so a regression shows up as a
 * missing or unexpected finding rather than as a silent diff in a report file.
 */
export interface BaselineFixture {
  version: 1;
  fixture: string;
  authorizationRequired: boolean;
  /** `recorded` baselines are comparable; `pending-authorization` ones are not. */
  status: "recorded" | "pending-authorization";
  expectedReportedCheckIds: string[];
  ignoredCheckIds?: IgnoredBaselineCheck[];
  notes?: string[];
}

export interface BaselineComparison {
  ok: boolean;
  fixture: string;
  status: BaselineFixture["status"];
  reportedCheckIds: string[];
  missingCheckIds: string[];
  unexpectedCheckIds: string[];
  ignoredCheckIds: string[];
  reportedFindings: number;
  reason?: string;
}

/** Read a baseline document from disk. */
export async function loadBaseline(path: string): Promise<BaselineFixture> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as BaselineFixture;
}

/**
 * Compare a run report against a recorded baseline. Reported means confirmed or
 * probable; discarded candidates and ignored checks are excluded. A pending
 * baseline cannot be validated yet and is never reported as passing.
 */
export function compareBaseline(report: Report, baseline: BaselineFixture): BaselineComparison {
  const ignored = new Set((baseline.ignoredCheckIds ?? []).map((entry) => entry.checkId));
  const reportedFindings = report.findings.filter(
    (finding) =>
      isReported(finding) &&
      typeof finding.checkId === "string" &&
      finding.checkId.length > 0 &&
      !ignored.has(finding.checkId),
  );
  const reportedCheckIds = [
    ...new Set(
      reportedFindings.flatMap((finding) =>
        typeof finding.checkId === "string" && finding.checkId.length > 0
          ? [finding.checkId]
          : [],
      ),
    ),
  ].sort();

  if (baseline.status !== "recorded") {
    return {
      ok: false,
      fixture: baseline.fixture,
      status: baseline.status,
      reportedCheckIds,
      missingCheckIds: [],
      unexpectedCheckIds: [],
      ignoredCheckIds: [...ignored].sort(),
      reportedFindings: reportedFindings.length,
      reason: "baseline has not been recorded against an authorized target",
    };
  }

  const expected = new Set(baseline.expectedReportedCheckIds);
  const missingCheckIds = [...expected].filter((id) => !reportedCheckIds.includes(id)).sort();
  const unexpectedCheckIds = reportedCheckIds.filter((id) => !expected.has(id));

  return {
    ok: missingCheckIds.length === 0 && unexpectedCheckIds.length === 0,
    fixture: baseline.fixture,
    status: baseline.status,
    reportedCheckIds,
    missingCheckIds,
    unexpectedCheckIds,
    ignoredCheckIds: [...ignored].sort(),
    reportedFindings: reportedFindings.length,
    reason:
      missingCheckIds.length > 0 || unexpectedCheckIds.length > 0
        ? "reported checks do not match the recorded baseline"
        : "reported checks match the recorded baseline",
  };
}
