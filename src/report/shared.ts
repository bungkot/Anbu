import type { Methodology, Report } from "../model/report.js";
import type { Finding, Severity } from "../model/finding.js";

export interface RenderOptions {
  /** Include discarded/unverified findings. Default: only confirmed and probable. */
  includeDiscarded?: boolean;
}

/** A finding is reported by default only when verification confirmed or retained it. */
export function isReported(finding: Finding): boolean {
  return finding.status === "confirmed" || finding.status === "probable";
}

export function selectFindings(report: Report, options: RenderOptions = {}): Finding[] {
  if (options.includeDiscarded === true) return [...report.findings];
  return report.findings.filter(isReported);
}

export function buildMethodology(modelAssisted: boolean, deterministicChecks: number): Methodology {
  return {
    framework: "OWASP Top 10:2025",
    approach:
      "Deterministic, guardrailed checks run first over the crawled attack surface; " +
      (modelAssisted
        ? "the LLM planner then selects additional in-scope checks and observations."
        : "the LLM planner was unavailable, so only deterministic checks ran."),
    deterministicChecks,
    modelAssisted,
    verification:
      "Every candidate finding is reproduced by re-running its originating check against the " +
      "captured evidence. Candidates that cannot be reproduced, lack valid evidence, or need " +
      "an approval that was not granted are withheld or marked probable.",
  };
}

export interface FindingSummary {
  reported: number;
  confirmed: number;
  probable: number;
  discarded: number;
  bySeverity: Record<Severity, number>;
}

export function summarizeFindings(findings: readonly Finding[]): FindingSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  let confirmed = 0;
  let probable = 0;
  let discarded = 0;
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    if (finding.status === "confirmed") confirmed += 1;
    else if (finding.status === "probable") probable += 1;
    else discarded += 1;
  }
  return {
    reported: confirmed + probable,
    confirmed,
    probable,
    discarded,
    bySeverity,
  };
}

/** Escape a value for use inside a Markdown table cell. */
export function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** Render a value as inline code, neutralizing backticks in untrusted text. */
export function markdownCode(value: string): string {
  const safe = value.replace(/`/g, "'");
  return `\`${safe}\``;
}

/** Format a severity/confidence pair consistently across renderers. */
export function formatSeverity(severity: Severity): string {
  return severity.toUpperCase();
}
