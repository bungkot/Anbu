import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import {
  captureAll,
  fetchPrimary,
  firstMatch,
  materialize,
  readOptionString,
  withQuery,
} from "./util.js";

/** Benign marker command. It produces an error only if the shell executes it. */
export const COMMAND_MARKER = "anbumarker";

const COMMAND_ERROR_SIGNATURES: readonly RegExp[] = [
  /command not found/i,
  /is not recognized as an internal or external command/i,
  /sh:\s*\S*anbumarker/i,
  /bash:\s*\S*anbumarker/i,
  /cmd\.exe:\s*\S*anbumarker/i,
  /anbumarker:\s*not found/i,
  /anbumarker:\s*command not found/i,
];

const COMMAND_PAYLOADS: readonly string[] = [
  `;${COMMAND_MARKER}`,
  `|${COMMAND_MARKER}`,
  `&&${COMMAND_MARKER}`,
  `$(${COMMAND_MARKER})`,
  "`" + COMMAND_MARKER + "`",
  `%0a${COMMAND_MARKER}`,
];

export interface CommandInjectionProbe {
  payload: string;
  response: CheckResponse;
}

export interface CommandInjectionObservation {
  url: string;
  parameter: string;
  baseline: CheckResponse;
  probes: CommandInjectionProbe[];
}

/**
 * Pure analyzer: report only when the marker command appears in the response
 * together with a shell error signature. Mere reflection is not reported as
 * command injection, because that is an XSS signal instead.
 */
export function analyzeCommandInjection(
  observation: CommandInjectionObservation,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const baselineBody = observation.baseline.bodyText;

  for (const probe of observation.probes) {
    const body = probe.response.bodyText;
    if (body.length === 0) continue;
    if (!body.includes(COMMAND_MARKER)) continue;
    if (baselineBody.includes(COMMAND_MARKER)) continue;
    const match = firstMatch(body, COMMAND_ERROR_SIGNATURES);
    if (match === undefined) continue;
    findings.push({
      title: "Command injection marker executed on the server",
      affected: { url: observation.url, parameter: observation.parameter },
      severity: "high",
      reproduction: [
        `Send GET ${observation.url} with ${observation.parameter}=${probe.payload} and inspect the response body.`,
      ],
      remediation:
        "Avoid shell execution with user input; use structured APIs and strict allowlists, and never pass request data to a shell.",
      details: `Payload ${probe.payload} produced the shell error "${match[0]}".`,
      falsePositiveAnalysis:
        "The marker command was not present in the baseline and the response contains a shell error naming the marker, so the payload reached a command interpreter.",
    });
  }

  return findings;
}

export const commandInjectionCheck: Check = {
  metadata: {
    id: "command-injection",
    toolName: "check_command_injection",
    title: "OS command injection probes",
    description:
      "Tests command separators and substitution syntax on reflected input and requires a shell error signature.",
    category: "A05",
    categories: ["A05"],
    cwe: "CWE-78",
    relatedCwes: ["CWE-88", "CWE-116"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: COMMAND_PAYLOADS.length + 1,
    references: [
      "https://owasp.org/Top10/A05_2025-Injection/",
      "https://cwe.mitre.org/data/definitions/78.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const parameter = input.parameter ?? readOptionString(input.options, "parameter");
    if (parameter === undefined) {
      return checkResult(
        ctx,
        [],
        [],
        undefined,
        "command-injection check requires a parameter name",
      );
    }

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "command-injection check received no response");
    }

    const probes: CommandInjectionProbe[] = [];
    const pairs = [{ request: primary.request, response: primary.response }];
    for (const payload of COMMAND_PAYLOADS) {
      const result = await ctx.fetch({
        method: "GET",
        url: withQuery(input.url, parameter, payload),
        headers: input.headers,
      });
      if (!result.ok || result.response === undefined) continue;
      probes.push({ payload, response: result.response });
      pairs.push({ request: result.request, response: result.response });
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeCommandInjection({
      url: input.url,
      parameter,
      baseline: primary.response,
      probes,
    });
    return checkResult(
      ctx,
      materialize(commandInjectionCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
