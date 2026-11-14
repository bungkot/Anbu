import type { Finding } from "./finding.js";
import type { OwaspCategory } from "./scope.js";

export type CoverageStatus = "covered" | "not_applicable" | "not_run";

export interface CoverageEntry {
  category: OwaspCategory;
  status: CoverageStatus;
  findings: number;
}

export interface BudgetStatus {
  maxRequests: number;
  usedRequests: number;
  maxDurationMinutes: number;
  elapsedMinutes: number;
  maxModelTurns: number;
  usedModelTurns: number;
}

export interface Report {
  runId: string;
  scopeReference: string;
  generatedAt: string;
  findings: Finding[];
  coverage: CoverageEntry[];
  budgets: BudgetStatus;
  stopReason: string;
}
