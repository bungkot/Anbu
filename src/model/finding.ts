import type { OwaspCategory } from "./scope.js";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "confirmed" | "probable" | "unverified";
export type FindingStatus = "candidate" | "confirmed" | "probable" | "discarded";

/** Outcome of the verify state for one finding. */
export type VerificationStatus = "confirmed" | "probable" | "discarded";

export interface FindingVerification {
  status: VerificationStatus;
  /** Human-readable explanation of the reproduction outcome. */
  reason: string;
  /** True when a reproduction attempt was actually made. */
  attempted: boolean;
  /** Evidence captured by the reproduction attempt, when one exists. */
  evidenceId?: string;
}

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
  /** Stable id of the deterministic check that produced the finding. */
  checkId?: string;
  title: string;
  affected: Affected;
  evidence: EvidenceRef[];
  reproduction: string[];
  remediation: string;
  falsePositiveAnalysis?: string;
  /** Result of the verify state, present once verification has run. */
  verification?: FindingVerification;
  /** Extra deterministic detail (matched markers, versions, headers). */
  details?: string;
}
