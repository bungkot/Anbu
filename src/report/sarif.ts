import type { Finding, Severity } from "../model/finding.js";
import type { Report } from "../model/report.js";
import { type RenderOptions, selectFindings } from "./shared.js";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION = "2.1.0" as const;

type SarifLevel = "error" | "warning" | "note" | "none";

interface SarifMessage {
  text: string;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription: SarifMessage;
  help: SarifMessage;
  properties: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: SarifMessage;
  partialFingerprints: Record<string, string>;
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
  properties: Record<string, unknown>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifLog {
  $schema: string;
  version: typeof SARIF_VERSION;
  runs: SarifRun[];
}

function sarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    case "informational":
      return "none";
  }
}

function ruleIdFor(finding: Finding): string {
  return finding.checkId ?? finding.category;
}

/** SARIF 2.1.0 view of the report. Default output omits discarded findings. */
export function renderSarif(report: Report, options: RenderOptions = {}): string {
  const findings = selectFindings(report, options);
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
    const ruleId = ruleIdFor(finding);
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.title },
        help: { text: finding.remediation },
        properties: {
          category: finding.category,
          cwe: finding.cwe,
          confidence: finding.confidence,
        },
      });
    }

    results.push({
      ruleId,
      level: sarifLevel(finding.severity),
      message: { text: finding.title },
      partialFingerprints: { findingId: finding.id },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.affected.url },
          },
        },
      ],
      properties: {
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence,
        status: finding.status,
        evidence: finding.evidence.map((ref) => ref.evidenceId),
        reproduction: finding.reproduction,
        remediation: finding.remediation,
        falsePositiveAnalysis: finding.falsePositiveAnalysis,
      },
    });
  }

  const log: SarifLog = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "Anbu",
            informationUri: "https://owasp.org/Top10/2025/",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(log, null, 2);
}
