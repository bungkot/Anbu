import type { Report } from "../model/report.js";
import { type RenderOptions, selectFindings, summarizeFindings } from "./shared.js";

/**
 * Machine-readable report. By default only confirmed and probable findings are
 * included; pass `includeDiscarded` to embed the full candidate set.
 */
export function renderJson(report: Report, options: RenderOptions = {}): string {
  const findings = selectFindings(report, options);
  const summary = summarizeFindings(report.findings);
  const payload = {
    ...report,
    findings,
    summary,
    withheldFindings: report.findings.length - findings.length,
  };
  return JSON.stringify(payload, null, 2);
}
