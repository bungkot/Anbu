import type { FindingCheckInput } from "../../model/finding.js";
import { redactCredentialText, redactCredentialValue } from "../../store/evidence-store.js";
import type { CheckInput } from "./types.js";

export interface SanitizedCheckInput {
  /** Closed input retained on a finding for reproduction. */
  input: FindingCheckInput;
  /**
   * True when redaction changed a value. A redacted input cannot be replayed
   * faithfully, so verification must not treat a failed replay as a
   * reproduction failure.
   */
  redacted: boolean;
}

/**
 * Redact a request body without a content type. JSON bodies are redacted
 * structurally so nested credential fields are caught; anything else is
 * redacted with the shared text patterns.
 */
function sanitizeBody(body: string): { value: string; redacted: boolean } {
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(body) as unknown;
      const redactedValue = redactCredentialValue(parsed);
      return {
        value: JSON.stringify(redactedValue),
        // Compare parsed values so reformatting whitespace is not a redaction.
        redacted: JSON.stringify(redactedValue) !== JSON.stringify(parsed),
      };
    } catch {
      // Not JSON; fall through to text redaction.
    }
  }
  const value = redactCredentialText(body);
  return { value, redacted: value !== body };
}

function sanitizeOptions(options: Record<string, unknown>): {
  value: Record<string, unknown>;
  redacted: boolean;
} {
  const redactedValue = redactCredentialValue(options);
  if (redactedValue === null || typeof redactedValue !== "object" || Array.isArray(redactedValue)) {
    return { value: options, redacted: false };
  }
  const value = redactedValue as Record<string, unknown>;
  return { value, redacted: JSON.stringify(value) !== JSON.stringify(options) };
}

/**
 * Project a check input onto the closed, sanitized shape retained on a
 * finding. Headers and credentials are never stored: checks authenticate
 * through the guarded client, and option values are redacted with the same
 * rules as evidence artifacts.
 */
export function sanitizeCheckInput(input: CheckInput): SanitizedCheckInput {
  const stored: FindingCheckInput = {};
  let redacted = false;

  const method = input.method?.trim().toUpperCase();
  if (method !== undefined && method.length > 0 && method !== "GET") stored.method = method;

  const parameter = input.parameter?.trim();
  if (parameter !== undefined && parameter.length > 0) stored.parameter = parameter;

  if (input.body !== undefined) {
    const body = sanitizeBody(input.body);
    stored.body = body.value;
    redacted = redacted || body.redacted;
  }

  if (input.options !== undefined) {
    const options = sanitizeOptions(input.options);
    stored.options = options.value;
    redacted = redacted || options.redacted;
  }

  if (redacted) stored.redacted = true;
  return { input: stored, redacted };
}
