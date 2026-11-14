import type { AuditEntry } from "../../../src/audit/log.js";
import type { Finding } from "../../../src/model/finding.js";
import type { CoverageEntry, Report } from "../../../src/model/report.js";
import { REPORT_VERSION } from "../../../src/model/report.js";
import { OWASP_CATEGORIES } from "../../../src/model/scope.js";
import { buildMethodology } from "../../../src/report/shared.js";

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "sha256:confirmed",
    category: "A05",
    cwe: "CWE-89",
    severity: "high",
    confidence: "confirmed",
    status: "confirmed",
    checkId: "sqli",
    title: "SQL error message reflected after an injection probe",
    affected: { url: "https://example.test/search", parameter: "q" },
    evidence: [{ evidenceId: "sha256:evidence", sha256: "evidence", path: "artifacts/evidence.json" }],
    reproduction: ["Send GET https://example.test/search with q=' and inspect the response body."],
    remediation: "Use parameterized queries or a query builder for every database call.",
    falsePositiveAnalysis: "The error signature appears only after the probe.",
    verification: {
      status: "confirmed",
      reason: "the originating check reproduced the finding",
      attempted: true,
      evidenceId: "sha256:evidence",
    },
    ...overrides,
  };
}

export function makeAuditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    seq: 1,
    timestamp: "2026-06-01T00:00:00.000Z",
    runId: "run-1",
    event: "run.start",
    prevHash: "0".repeat(64),
    hash: "hash-1",
    ...overrides,
  };
}

export function makeReport(overrides: Partial<Report> = {}): Report {
  const findings: Finding[] = [
    makeFinding(),
    makeFinding({
      id: "sha256:probable",
      status: "probable",
      confidence: "probable",
      severity: "medium",
      checkId: "xss",
      title: "XSS probe reflected without obvious HTML encoding",
      verification: {
        status: "probable",
        reason: "encoding could not be confirmed",
        attempted: false,
      },
    }),
    makeFinding({
      id: "sha256:discarded",
      status: "discarded",
      confidence: "unverified",
      severity: "low",
      checkId: "logging",
      title: "Discarded candidate",
      verification: {
        status: "discarded",
        reason: "the originating check did not reproduce the finding on re-run",
        attempted: true,
      },
    }),
  ];

  const coverage: CoverageEntry[] = OWASP_CATEGORIES.map((category) => {
    if (category === "A05") {
      return { category, status: "covered", findings: 3, checks: 2 };
    }
    if (category === "A01") {
      return { category, status: "not_run", findings: 0, checks: 0 };
    }
    return { category, status: "not_applicable", findings: 0, checks: 0 };
  });

  return {
    reportVersion: REPORT_VERSION,
    runId: "run-1",
    scopeReference: "PENTEST-2026-001",
    generatedAt: "2026-06-01T00:00:00.000Z",
    methodology: buildMethodology(true, 20),
    findings,
    coverage,
    budgets: {
      maxRequests: 800,
      usedRequests: 120,
      maxDurationMinutes: 60,
      elapsedMinutes: 1.5,
      maxModelTurns: 120,
      usedModelTurns: 10,
    },
    stopReason: "completed",
    audit: {
      path: "workspace/evidence/run-1/audit.log",
      entries: 2,
      integrity: "ok",
      events: [
        makeAuditEntry({ seq: 1, event: "run.start" }),
        makeAuditEntry({ seq: 2, event: "run.end", prevHash: "hash-1", hash: "hash-2" }),
      ],
    },
    ...overrides,
  };
}
