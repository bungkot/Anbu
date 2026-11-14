import type { CandidateFinding, Check, CheckResponse, CheckResult } from "./types.js";
import { checkResult } from "./types.js";
import {
  captureAll,
  fetchPrimary,
  isSuccessStatus,
  materialize,
  readOptionString,
} from "./util.js";

const BOUNDARY = "anbu-upload-check";
const DEFAULT_MARKER = "anbumarker";

export interface UploadObservation {
  url: string;
  upload: CheckResponse;
  retrieval?: CheckResponse;
  marker: string;
}

function multipartBody(
  fieldName: string,
  filename: string,
  contentType: string,
  content: string,
): string {
  return [
    `--${BOUNDARY}`,
    `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    "",
    content,
    `--${BOUNDARY}--`,
    "",
  ].join("\r\n");
}

function extractStoredPath(body: string): string | undefined {
  const patterns: readonly RegExp[] = [
    /"(?:url|path|location|file|filename)"\s*:\s*"([^"]+)"/i,
    /href=["']([^"']+)["']/i,
    /src=["']([^"']+)["']/i,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(body);
    if (match !== null) return match[1];
  }
  return undefined;
}

function resolveStoredPath(baseUrl: string, storedPath: string): string | undefined {
  try {
    return new URL(storedPath, baseUrl).toString();
  } catch {
    return undefined;
  }
}

/**
 * Pure analyzer: report when an uploaded harmless HTML file is stored and
 * served back with its marker, which indicates unrestricted upload and stored
 * XSS potential.
 */
export function analyzeUpload(observation: UploadObservation): CandidateFinding[] {
  if (!isSuccessStatus(observation.upload.status)) return [];
  const retrieval = observation.retrieval;
  if (retrieval === undefined) return [];
  if (!isSuccessStatus(retrieval.status)) return [];
  if (!retrieval.bodyText.includes(observation.marker)) return [];

  return [
    {
      title: "Unrestricted file upload is stored and served",
      affected: { url: observation.url },
      severity: "high",
      reproduction: [
        `Send POST ${observation.url} with a multipart form containing a harmless HTML file and marker, then request the returned file URL.`,
      ],
      remediation:
        "Validate upload content by type and extension, store files outside the web root, serve them with a safe content type, and scan them for active content.",
      details:
        "The upload was accepted and the stored file was retrievable with the original marker content.",
      falsePositiveAnalysis:
        "The uploaded file was served back unchanged from the server, so the upload endpoint does not neutralize active content.",
    },
  ];
}

export const uploadCheck: Check = {
  metadata: {
    id: "upload",
    toolName: "check_upload",
    title: "Unrestricted file upload",
    description:
      "Tests unrestricted upload with harmless, non-executable HTML payloads and verifies whether the stored file is served.",
    category: "A06",
    categories: ["A06"],
    cwe: "CWE-434",
    relatedCwes: ["CWE-646", "CWE-79"],
    readOnly: false,
    requiresApproval: true,
    severity: "high",
    maxRequests: 3,
    references: [
      "https://owasp.org/Top10/A06_2025-Insecure_Design/",
      "https://cwe.mitre.org/data/definitions/434.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const fieldName = readOptionString(input.options, "fieldName") ?? "file";
    const filename = readOptionString(input.options, "filename") ?? "anbu-check.html";
    const contentType = readOptionString(input.options, "contentType") ?? "text/html";
    const content = readOptionString(input.options, "content") ?? `<p>${DEFAULT_MARKER}</p>`;
    const marker = readOptionString(input.options, "marker") ?? DEFAULT_MARKER;

    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "upload check received no response");
    }

    const headers: Record<string, string> = {
      ...(input.headers ?? {}),
      "content-type": `multipart/form-data; boundary=${BOUNDARY}`,
    };
    const result = await ctx.fetch({
      method: "POST",
      url: input.url,
      headers,
      body: multipartBody(fieldName, filename, contentType, content),
    });
    if (!result.ok || result.response === undefined) {
      return checkResult(ctx, [], [], result.error ?? "upload probe failed");
    }

    const pairs = [
      { request: primary.request, response: primary.response },
      { request: result.request, response: result.response },
    ];
    let retrieval: CheckResponse | undefined;
    const storedPath = extractStoredPath(result.response.bodyText);
    if (storedPath !== undefined) {
      const resolved = resolveStoredPath(input.url, storedPath);
      if (resolved !== undefined) {
        const retrievalResult = await ctx.fetch({ method: "GET", url: resolved });
        if (retrievalResult.ok && retrievalResult.response !== undefined) {
          retrieval = retrievalResult.response;
          pairs.push({
            request: retrievalResult.request,
            response: retrievalResult.response,
          });
        }
      }
    }

    const evidence = await captureAll(ctx, pairs);
    const candidates = analyzeUpload({
      url: input.url,
      upload: result.response,
      retrieval,
      marker,
    });
    return checkResult(
      ctx,
      materialize(uploadCheck.metadata, candidates, evidence, input),
      evidence,
    );
  },
};
