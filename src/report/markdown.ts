import type { Finding } from "../model/finding.js";
import type { Report } from "../model/report.js";
import { OWASP_CATEGORY_NAMES } from "../model/scope.js";
import {
  type RenderOptions,
  formatSeverity,
  markdownCell,
  markdownCode,
  selectFindings,
  summarizeFindings,
} from "./shared.js";

function findingSection(finding: Finding, index: number): string[] {
  const lines: string[] = [];
  const parameter = finding.affected.parameter === undefined ? "" : `?${finding.affected.parameter}`;
  lines.push(`### ${index}. [${formatSeverity(finding.severity)}] ${finding.title}`);
  lines.push("");
  lines.push(`- **ID:** ${markdownCode(finding.id)}`);
  lines.push(`- **Category:** ${finding.category} ${OWASP_CATEGORY_NAMES[finding.category]}`);
  if (finding.cwe !== undefined) lines.push(`- **CWE:** ${markdownCell(finding.cwe)}`);
  lines.push(`- **Status:** ${finding.status} (confidence: ${finding.confidence})`);
  lines.push(`- **Affected:** ${markdownCell(`${finding.affected.url}${parameter}`)}`);
  lines.push("");
  lines.push("**Reproduction**");
  lines.push("");
  if (finding.reproduction.length === 0) {
    lines.push("_No reproduction steps were recorded._");
  } else {
    for (const step of finding.reproduction) lines.push(`1. ${step}`);
  }
  lines.push("");
  lines.push("**Evidence**");
  lines.push("");
  if (finding.evidence.length === 0) {
    lines.push("_No evidence was recorded._");
  } else {
    for (const ref of finding.evidence) {
      lines.push(`- ${markdownCode(ref.evidenceId)} — ${markdownCell(ref.path)}`);
    }
  }
  lines.push("");
  lines.push("**Remediation**");
  lines.push("");
  lines.push(finding.remediation);
  if (finding.details !== undefined) {
    lines.push("");
    lines.push(`**Details:** ${finding.details}`);
  }
  if (finding.falsePositiveAnalysis !== undefined) {
    lines.push("");
    lines.push(`**False-positive analysis:** ${finding.falsePositiveAnalysis}`);
  }
  if (finding.verification !== undefined) {
    lines.push("");
    lines.push(
      `- **Verification:** ${finding.verification.status} — ${finding.verification.reason}` +
        (finding.verification.evidenceId === undefined
          ? ""
          : ` (${markdownCode(finding.verification.evidenceId)})`),
    );
  }
  lines.push("");
  return lines;
}

/** Human-readable Markdown report. Default output omits discarded findings. */
export function renderMarkdown(report: Report, options: RenderOptions = {}): string {
  const findings = selectFindings(report, options);
  const summary = summarizeFindings(report.findings);
  const lines: string[] = [];

  lines.push("# Anbu Pentest Report");
  lines.push("");
  lines.push(`- **Run ID:** ${markdownCell(report.runId)}`);
  lines.push(`- **Scope authorization:** ${markdownCell(report.scopeReference)}`);
  lines.push(`- **Generated:** ${markdownCell(report.generatedAt)}`);
  lines.push(`- **Stop reason:** ${markdownCell(report.stopReason)}`);
  lines.push(`- **Report version:** ${report.reportVersion}`);
  lines.push("");

  lines.push("## Executive summary");
  lines.push("");
  lines.push(`Reported findings: **${summary.reported}** (${summary.confirmed} confirmed, ${summary.probable} probable)`);
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  for (const severity of ["critical", "high", "medium", "low", "informational"] as const) {
    lines.push(`| ${formatSeverity(severity)} | ${summary.bySeverity[severity]} |`);
  }
  lines.push("");
  if (summary.discarded > 0 && options.includeDiscarded !== true) {
    lines.push(`${summary.discarded} candidate(s) were withheld because they were not confirmed or probable.`);
    lines.push("");
  }

  lines.push("## Methodology");
  lines.push("");
  lines.push(`- **Framework:** ${report.methodology.framework}`);
  lines.push(`- **Approach:** ${report.methodology.approach}`);
  lines.push(`- **Deterministic checks:** ${report.methodology.deterministicChecks}`);
  lines.push(`- **Model-assisted:** ${report.methodology.modelAssisted ? "yes" : "no"}`);
  lines.push(`- **Verification:** ${report.methodology.verification}`);
  lines.push("");

  lines.push("## Coverage");
  lines.push("");
  lines.push("| Category | Name | Status | Checks | Findings |");
  lines.push("|---|---|---|---|---|");
  for (const entry of report.coverage) {
    lines.push(
      `| ${entry.category} | ${markdownCell(OWASP_CATEGORY_NAMES[entry.category])} | ${entry.status} | ${entry.checks} | ${entry.findings} |`,
    );
  }
  lines.push("");

  lines.push("## Budgets");
  lines.push("");
  lines.push("| Budget | Used | Maximum |");
  lines.push("|---|---|---|");
  lines.push(`| Requests | ${report.budgets.usedRequests} | ${report.budgets.maxRequests} |`);
  lines.push(
    `| Duration (minutes) | ${report.budgets.elapsedMinutes.toFixed(1)} | ${report.budgets.maxDurationMinutes} |`,
  );
  lines.push(`| Model turns | ${report.budgets.usedModelTurns} | ${report.budgets.maxModelTurns} |`);
  lines.push("");

  lines.push("## Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("_No confirmed or probable findings._");
    lines.push("");
  } else {
    let index = 1;
    for (const finding of findings) {
      lines.push(...findingSection(finding, index));
      index += 1;
    }
  }

  lines.push("## Audit log");
  lines.push("");
  lines.push(`- **Path:** ${markdownCell(report.audit.path)}`);
  lines.push(`- **Entries:** ${report.audit.entries}`);
  lines.push(`- **Integrity:** ${report.audit.integrity}`);
  if (report.audit.brokenAt !== undefined) {
    lines.push(`- **Broken at sequence:** ${report.audit.brokenAt}`);
  }
  lines.push("");
  if (report.audit.events.length > 0) {
    lines.push("| Seq | Timestamp | Event | Decision | Reason |");
    lines.push("|---|---|---|---|---|");
    for (const event of report.audit.events) {
      lines.push(
        `| ${event.seq} | ${markdownCell(event.timestamp)} | ${markdownCell(event.event)} | ${markdownCell(event.decision ?? "")} | ${markdownCell(event.reason ?? "")} |`,
      );
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push("Generated by Anbu. Target responses are untrusted data; findings require human review.");
  lines.push("");
  return lines.join("\n");
}
