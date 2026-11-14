import type { OwaspCategory } from "./scope.js";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "confirmed" | "probable" | "unverified";
export type FindingStatus = "candidate" | "confirmed" | "probable" | "discarded";

export interface EvidenceRef {
  evidenceId: string;
  sha256: string;
  path: string;
}

export interface Affected {
  url: string;
  parameter?: string;
  endpoint?: string;
}

export interface Finding {
  id: string;
  category: OwaspCategory;
  cwe?: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  title: string;
  affected: Affected;
  evidence: EvidenceRef[];
  reproduction: string[];
  remediation: string;
  falsePositiveAnalysis?: string;
  /** Extra deterministic detail (matched markers, versions, headers). */
  details?: string;
}
