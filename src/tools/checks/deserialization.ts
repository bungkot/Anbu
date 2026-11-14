import type { CandidateFinding, Check, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import { captureAll, fetchPrimary, materialize, readOptionString } from "./util.js";

const DESERIALIZATION_MARKERS: ReadonlyArray<{
  test: (body: string) => boolean;
  label: string;
}> = [
  {
    test: (body) => body.includes("rO0AB"),
    label: ".NET BinaryFormatter serialization header",
  },
  {
    test: (body) => body.includes("\u00AC\u00ED\u0000\u0005"),
    label: "Java serialization magic bytes",
  },
  {
    test: (body) => /aced\s*00\s*05/i.test(body),
    label: "Java serialization magic bytes",
  },
  { test: (body) => /O:\d+:"/.test(body), label: "PHP serialized object" },
  { test: (body) => /a:\d+:\{/.test(body), label: "PHP serialized array" },
  {
    test: (body) => body.includes("gASV"),
    label: "Python pickle serialization header",
  },
  {
    test: (body) => body.includes("\u0080\u0004"),
    label: "Python pickle protocol 4 header",
  },
  {
    test: (body) => /ObjectInputStream/i.test(body),
    label: "Java ObjectInputStream reference",
  },
];

export interface DeserializationObservation {
  url: string;
  body: string;
}

/**
 * Pure analyzer: detect serialization formats that are commonly unsafe when
 * they are deserialized without strict type validation.
 */
export function analyzeDeserialization(
  observation: DeserializationObservation,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const body = observation.body;
  if (body.length === 0) return findings;

  const seen = new Set<string>();
  for (const marker of DESERIALIZATION_MARKERS) {
    if (!marker.test(body)) continue;
    if (seen.has(marker.label)) continue;
    seen.add(marker.label);
    findings.push({
      title: `Insecure deserialization marker detected (${marker.label})`,
      affected: { url: observation.url },
      severity: "high",
      reproduction: [`Inspect the response or request body served by ${observation.url}.`],
      remediation:
        "Avoid native serialization formats for untrusted input; use JSON with strict schemas, or a safe serializer with an explicit allowed-class allowlist.",
      details: `The content contains a ${marker.label}.`,
      falsePositiveAnalysis:
        "The marker identifies a serialization format that is unsafe to deserialize from untrusted sources; it does not prove exploitation by itself.",
    });
  }

  return findings;
}

export const deserializationCheck: Check = {
  metadata: {
    id: "deserialization",
    toolName: "check_deserialization",
    title: "Insecure deserialization markers",
    description:
      "Detects Java, .NET, PHP, and Python serialization markers and gadget surface in responses.",
    category: "A08",
    categories: ["A08"],
    cwe: "CWE-502",
    relatedCwes: ["CWE-134", "CWE-1104"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 1,
    references: [
      "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/",
      "https://cwe.mitre.org/data/definitions/502.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const supplied = readOptionString(input.options, "body");
    if (supplied !== undefined) {
      const candidates = analyzeDeserialization({ url: input.url, body: supplied });
      return checkResult(
        ctx,
        materialize(deserializationCheck.metadata, candidates, [], input),
        [],
      );
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "deserialization check received no response");
    }

    const evidence = await captureAll(ctx, [
      { request: primary.request, response: primary.response },
    ]);
    const candidates = analyzeDeserialization({
      url: input.url,
      body: primary.response.bodyText,
    });
    return checkResult(
      ctx,
      materialize(deserializationCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
