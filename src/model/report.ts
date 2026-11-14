import type { AuditEntry } from "../audit/log.js";
import type { Finding } from "./finding.js";
import type { OwaspCategory } from "./scope.js";

/** Version of the report envelope. Bump when the shape changes. */
export const REPORT_VERSION = 1;

export type CoverageStatus = "covered" | "not_applicable" | "not_run";

export interface CoverageEntry {
  category: OwaspCategory;
  status: CoverageStatus;
  findings: number;
  /** Registered checks that were executed for this category. */
  checks: number;
}

export interface BudgetStatus {
  maxRequests: number;
  usedRequests: number;
  maxDurationMinutes: number;
  elapsedMinutes: number;
  maxModelTurns: number;
  usedModelTurns: number;
}

export interface Methodology {
  framework: "OWASP Top 10:2025";
  approach: string;
  deterministicChecks: number;
  modelAssisted: boolean;
  verification: string;
}

export interface AuditSummary {
  /** Path to the append-only audit log shipped with the run. */
  path: string;
  entries: number;
  integrity: "ok" | "failed" | "unknown";
  brokenAt?: number;
  events: AuditEntry[];
}

export interface Report {
  reportVersion: number;
  runId: string;
  scopeReference: string;
  generatedAt: string;
  methodology: Methodology;
  findings: Finding[];
  coverage: CoverageEntry[];
  budgets: BudgetStatus;
  stopReason: string;
  audit: AuditSummary;
}
