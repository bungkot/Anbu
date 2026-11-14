import type {
  CaptureInput,
  CaptureResult,
  CompareResult,
  EvidenceStore,
  ParseResult,
} from "../store/evidence-store.js";

export interface CaptureEvidenceInput extends CaptureInput {
  /**
   * Redact credentials, cookies, and tokens before the artifact is written.
   * Defaults to true; disabling it is intended for non-sensitive fixtures only.
   */
  redact?: boolean;
}

/**
 * Tool: store a request/response artifact with sanitization and a content hash.
 * Returns the evidence id, relative path, and SHA-256 of the stored artifact.
 */
export async function captureEvidence(
  store: EvidenceStore,
  input: CaptureEvidenceInput,
): Promise<CaptureResult> {
  return store.capture(input, { redact: input.redact });
}

/** Tool: compare a candidate response against a baseline artifact. */
export async function compareEvidence(
  store: EvidenceStore,
  candidateEvidenceId: string,
  baselineEvidenceId: string,
): Promise<CompareResult> {
  return store.compare(candidateEvidenceId, baselineEvidenceId);
}

/**
 * Tool: extract structured facts (headers, cookies, forms, links, framework
 * markers) from stored evidence. Performs no network calls.
 */
export async function parseResponse(
  store: EvidenceStore,
  evidenceId: string,
): Promise<ParseResult> {
  return store.parse(evidenceId);
}
