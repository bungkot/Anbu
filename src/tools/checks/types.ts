import { createHash } from "node:crypto";
import type { AuditLog } from "../../audit/log.js";
import type {
  Affected,
  Confidence,
  EvidenceRef,
  Finding,
  Severity,
} from "../../model/finding.js";
import type { OwaspCategory, Scope } from "../../model/scope.js";
import type { EvidenceStore } from "../../store/evidence-store.js";
import type { GuardedHttpClient, HttpResponseSummary } from "../http.js";

export type { EvidenceRef };

/** Default per-check request cap when a check does not declare one. */
export const DEFAULT_CHECK_MAX_REQUESTS = 20;

/**
 * Static description of a deterministic check. The planner and the report use
 * this metadata; it is versioned together with the check implementation.
 */
export interface CheckMetadata {
  /** Stable identifier, for example `sqli`. */
  id: string;
  /** Agent-facing tool name, for example `check_sqli`. */
  toolName: string;
  title: string;
  description: string;
  /** Primary OWASP Top 10:2025 category. */
  category: OwaspCategory;
  /** Every OWASP category the check contributes evidence to. */
  categories: OwaspCategory[];
  /** Primary CWE, when one maps cleanly. */
  cwe?: string;
  /** Additional related CWEs. */
  relatedCwes: string[];
  /** True when the check only issues read-only methods and cannot change state. */
  readOnly: boolean;
  /**
   * True when the check must not run without an explicit human approval gate.
   * Every non-read-only check must set this to true.
   */
  requiresApproval: boolean;
  /** Default severity for findings produced by this check. */
  severity: Severity;
  /** Hard cap on HTTP requests issued by a single run. */
  maxRequests: number;
  /** OWASP, CWE, or vendor references. */
  references: string[];
}

/** A normalized HTTP response used by analyzers. Never contains secrets. */
export interface CheckResponse {
  url: string;
  method: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodyText: string;
  bodyBytes: number;
  truncated: boolean;
  durationMs: number;
}

export interface CheckFetchInput {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface CheckFetchResult {
  ok: boolean;
  request: CheckFetchInput;
  response?: CheckResponse;
  error?: string;
  requiresApproval?: boolean;
}

export interface CheckCaptureRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface CheckCaptureResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
  bodyBytes?: number;
  truncated?: boolean;
  durationMs?: number;
}

/**
 * Runtime context handed to every check. `fetch` is the only way a check may
 * reach the network, so scope, deny, authorization, policy, rate limit, and
 * audit are applied uniformly.
 */
export interface CheckContext {
  scope: Scope;
  client: GuardedHttpClient;
  store: EvidenceStore;
  audit: AuditLog;
  now: () => Date;
  /** Per-run request cap. Enforced by `fetch`. */
  maxRequests: number;
  /** Requests issued by the current check run. */
  requestCount: number;
  fetch(input: CheckFetchInput): Promise<CheckFetchResult>;
  capture(
    request: CheckCaptureRequest,
    response: CheckCaptureResponse,
  ): Promise<EvidenceRef | undefined>;
}

/**
 * Closed input shape. Checks narrow this at runtime and reject unknown or
 * malformed values; they never accept free-form model output.
 */
export interface CheckInput {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  parameter?: string;
  evidenceId?: string;
  options?: Record<string, unknown>;
}

/** A finding before it has an identity and evidence attached. */
export interface CandidateFinding {
  title: string;
  affected: Affected;
  severity?: Severity;
  confidence?: Confidence;
  reproduction: string[];
  remediation: string;
  falsePositiveAnalysis?: string;
  details?: string;
}

export interface CheckResult {
  /** True when the check ran to completion (a skip is still a completed run). */
  ok: boolean;
  error?: string;
  skipped?: string;
  findings: Finding[];
  requests: number;
  evidence: EvidenceRef[];
}

export interface Check {
  metadata: CheckMetadata;
  run(ctx: CheckContext, input: CheckInput): Promise<CheckResult>;
}

export function toCheckResponse(summary: HttpResponseSummary, method: string): CheckResponse {
  return {
    url: summary.url,
    method,
    status: summary.status,
    statusText: summary.statusText,
    headers: summary.headers,
    bodyText: summary.bodyText,
    bodyBytes: summary.bodyBytes,
    truncated: summary.truncated,
    durationMs: summary.durationMs,
  };
}

/** Deterministic finding identity so the same evidence reproduces the same id. */
export function findingIdentity(
  metadata: CheckMetadata,
  candidate: CandidateFinding,
  evidence: readonly EvidenceRef[],
): string {
  return createHash("sha256")
    .update(metadata.id)
    .update("\n")
    .update(candidate.affected.url)
    .update("\n")
    .update(candidate.affected.parameter ?? "")
    .update("\n")
    .update(candidate.title)
    .update("\n")
    .update(evidence[0]?.sha256 ?? "")
    .digest("hex");
}

export function makeFinding(
  metadata: CheckMetadata,
  candidate: CandidateFinding,
  evidence: readonly EvidenceRef[] = [],
): Finding {
  return {
    id: `sha256:${findingIdentity(metadata, candidate, evidence)}`,
    category: metadata.category,
    cwe: metadata.cwe,
    severity: candidate.severity ?? metadata.severity,
    confidence: candidate.confidence ?? "probable",
    status: "candidate",
    checkId: metadata.id,
    title: candidate.title,
    affected: candidate.affected,
    evidence: [...evidence],
    reproduction: candidate.reproduction,
    remediation: candidate.remediation,
    falsePositiveAnalysis: candidate.falsePositiveAnalysis,
    details: candidate.details,
  };
}

export function checkResult(
  ctx: CheckContext,
  findings: Finding[],
  evidence: EvidenceRef[],
  error?: string,
  skipped?: string,
): CheckResult {
  return {
    ok: error === undefined,
    error,
    skipped,
    findings,
    requests: ctx.requestCount,
    evidence,
  };
}
