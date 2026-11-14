import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import { captureAll, fetchPrimary, materialize } from "./util.js";

/** Unique entity name used in the DTD probes. */
export const XXE_ENTITY = "anbuxxe";

const XXE_SIGNATURES: readonly RegExp[] = [
  /failed to load external entity/i,
  /external entity/i,
  /SAXParseException/i,
  /DOCTYPE is not allowed/i,
  /simplexml_load_string/i,
  /libxml/i,
  /no such file or directory/i,
  /permission denied/i,
];

const XXE_PAYLOADS: readonly string[] = [
  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE anbu [<!ENTITY ${XXE_ENTITY} SYSTEM "file:///nonexistent-anbu-xxe">]><anbu>&${XXE_ENTITY};</anbu>`,
  `<?xml version="1.0"?><!DOCTYPE anbu [<!ENTITY % ${XXE_ENTITY} SYSTEM "file:///nonexistent-anbu-xxe"> %${XXE_ENTITY};]><anbu/>`,
  `<?xml version="1.0"?><!DOCTYPE anbu SYSTEM "file:///nonexistent-anbu-xxe.dtd"><anbu/>`,
];

export interface XxeProbe {
  payload: string;
  response: CheckResponse;
}

export interface XxeObservation {
  url: string;
  baseline: CheckResponse;
  probes: XxeProbe[];
}

/**
 * Pure analyzer: report when an external entity probe is processed by the XML
 * parser. The probes point at a non-existent local file, so they never read a
 * real secret; the parser error is the signal.
 */
export function analyzeXxe(observation: XxeObservation): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineBody = observation.baseline.bodyText;

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    for (const pattern of XXE_SIGNATURES) {
      const match = pattern.exec(body);
      if (match === null) continue;
      if (pattern.test(baselineBody)) continue;
      const mentionsEntity = body.includes(XXE_ENTITY) || body.includes("file:///");
      if (!mentionsEntity) continue;
      findings.push({
        title: "XML external entity probe was processed by the parser",
        affected: { url: observation.url },
        severity: "high",
        reproduction: [
          `Send POST ${observation.url} with the external-entity XML payload and inspect the parser error.`,
        ],
        remediation:
          "Disable external entity and DTD processing in the XML parser (for example, `libxml_disable_entity_loader` or `setFeature(...external-general-entities, false)`); prefer JSON.",
        details: `The parser reported "${match[0]}" for an external entity probe.`,
        falsePositiveAnalysis:
          "The baseline did not contain the signature and the probe references a non-existent file, so the parser attempted to resolve the entity.",
      });
      break;
    }
  }

  return findings;
}

export const xxeCheck: Check = {
  metadata: {
    id: "xxe",
    toolName: "check_xxe",
    title: "XML external entity probes",
    description:
      "Tests XML parsers with safe external-entity probes that reference a non-existent local file.",
    category: "A05",
    categories: ["A05"],
    cwe: "CWE-611",
    relatedCwes: ["CWE-77", "CWE-91"],
    readOnly: false,
    requiresApproval: true,
    severity: "high",
    maxRequests: XXE_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A05_2025-Injection/",
      "https://cwe.mitre.org/data/definitions/611.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "xxe check received no response");
    }

    const headers: Record<string, string> = {
      ...(input.headers ?? {}),
      "content-type": "application/xml",
    };
    const probes: XxeProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of XXE_PAYLOADS) {
      const result = await ctx.fetch({
        method: "POST",
        url: input.url,
        headers,
        body: payload,
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ payload, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeXxe({ url: input.url, baseline: primary.response, probes });
    return checkResult(ctx, materialize(xxeCheck.metadata, candidates, evidence, input), evidence);
  },
};
