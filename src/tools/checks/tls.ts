import type {
  CandidateFinding,
  Check,
  CheckResult,
  EvidenceRef,
} from "./types.js";
import { checkResult } from "./types.js";
import {
  captureResponse,
  fetchPrimary,
  headerValue,
  materialize,
  readOptionRecord,
  readRecordBoolean,
  readRecordNumber,
  readRecordString,
} from "./util.js";

export interface TlsCertificateFacts {
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validUntil?: string;
  selfSigned?: boolean;
  hostnameMatches?: boolean;
  signatureAlgorithm?: string;
  keyAlgorithm?: string;
  keyBits?: number;
}

export interface TlsObservation {
  url: string;
  headers: Record<string, string>;
  protocol?: string;
  cipher?: string;
  certificate?: TlsCertificateFacts;
}

const WEAK_CIPHERS = /(^|[^a-z])(rc4|des|3des|des-ede|null|export|md5)([^a-z]|$)/i;
const NO_FORWARD_SECRECY = /TLS_RSA_|RSA_(?:AES|CHACHA)/i;

/** Parse an optional certificate-facts object supplied by an approved probe. */
export function parseTlsCertificate(value: unknown): TlsCertificateFacts | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const certificate: TlsCertificateFacts = {};
  const subject = readRecordString(record, "subject");
  const issuer = readRecordString(record, "issuer");
  const validFrom = readRecordString(record, "validFrom");
  const validUntil = readRecordString(record, "validUntil");
  const signatureAlgorithm = readRecordString(record, "signatureAlgorithm");
  const keyAlgorithm = readRecordString(record, "keyAlgorithm");
  const selfSigned = readRecordBoolean(record, "selfSigned");
  const hostnameMatches = readRecordBoolean(record, "hostnameMatches");
  const keyBits = readRecordNumber(record, "keyBits");
  if (subject !== undefined) certificate.subject = subject;
  if (issuer !== undefined) certificate.issuer = issuer;
  if (validFrom !== undefined) certificate.validFrom = validFrom;
  if (validUntil !== undefined) certificate.validUntil = validUntil;
  if (signatureAlgorithm !== undefined) certificate.signatureAlgorithm = signatureAlgorithm;
  if (keyAlgorithm !== undefined) certificate.keyAlgorithm = keyAlgorithm;
  if (selfSigned !== undefined) certificate.selfSigned = selfSigned;
  if (hostnameMatches !== undefined) certificate.hostnameMatches = hostnameMatches;
  if (keyBits !== undefined) certificate.keyBits = keyBits;
  return Object.keys(certificate).length > 0 ? certificate : undefined;
}

/** Pure analyzer for TLS protocol, cipher, and certificate posture. */
export function analyzeTls(
  observation: TlsObservation,
  now: Date = new Date(),
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const { url } = observation;

  if (observation.protocol !== undefined) {
    const protocol = observation.protocol.trim().toLowerCase();
    if (/(ssl\s*v?2|ssl\s*v?3|tls\s*v?1\.0|tls\s*v?1\.1)/.test(protocol)) {
      findings.push({
        title: `Deprecated TLS protocol in use (${observation.protocol})`,
        affected: { url },
        severity: "high",
        reproduction: [`Observe the TLS handshake for ${url} (approved TLS probe).`],
        remediation: "Disable TLS 1.0/1.1 and SSL; require TLS 1.2 or newer.",
        details: `Negotiated protocol: ${observation.protocol}`,
      });
    } else if (/tls\s*v?1\.2/.test(protocol)) {
      findings.push({
        title: "TLS 1.2 is enabled",
        affected: { url },
        severity: "low",
        reproduction: [`Observe the TLS handshake for ${url} (approved TLS probe).`],
        remediation: "Plan migration to TLS 1.3 and disable TLS 1.2 when clients allow.",
        details: `Negotiated protocol: ${observation.protocol}`,
      });
    }
  }

  if (observation.cipher !== undefined) {
    const cipher = observation.cipher;
    if (WEAK_CIPHERS.test(cipher)) {
      findings.push({
        title: "Weak TLS cipher suite in use",
        affected: { url },
        severity: "high",
        reproduction: [`Observe the TLS handshake for ${url} (approved TLS probe).`],
        remediation:
          "Disable RC4, DES, 3DES, NULL, export-grade, and MD5-based cipher suites.",
        details: `Negotiated cipher: ${cipher}`,
      });
    } else if (NO_FORWARD_SECRECY.test(cipher)) {
      findings.push({
        title: "TLS cipher suite does not provide forward secrecy",
        affected: { url },
        severity: "low",
        reproduction: [`Observe the TLS handshake for ${url} (approved TLS probe).`],
        remediation: "Prefer ECDHE/DHE key exchange suites.",
        details: `Negotiated cipher: ${cipher}`,
      });
    }
  }

  const certificate = observation.certificate;
  if (certificate !== undefined) {
    if (certificate.validUntil !== undefined) {
      const expiry = Date.parse(certificate.validUntil);
      if (!Number.isNaN(expiry) && expiry < now.getTime()) {
        findings.push({
          title: "TLS certificate has expired",
          affected: { url },
          severity: "high",
          reproduction: [`Inspect the certificate presented by ${url}.`],
          remediation: "Renew the certificate and deploy the new chain before expiry.",
          details: `Certificate expired at ${certificate.validUntil}.`,
        });
      }
    }
    if (certificate.validFrom !== undefined) {
      const start = Date.parse(certificate.validFrom);
      if (!Number.isNaN(start) && start > now.getTime()) {
        findings.push({
          title: "TLS certificate is not yet valid",
          affected: { url },
          severity: "high",
          reproduction: [`Inspect the certificate presented by ${url}.`],
          remediation: "Deploy a certificate whose validity window has started.",
          details: `Certificate valid from ${certificate.validFrom}.`,
        });
      }
    }
    if (certificate.selfSigned === true) {
      findings.push({
        title: "TLS certificate is self-signed",
        affected: { url },
        severity: "medium",
        reproduction: [`Inspect the certificate presented by ${url}.`],
        remediation: "Use a certificate issued by a trusted certificate authority.",
        details: certificate.issuer ?? "Self-signed certificate.",
      });
    }
    if (certificate.hostnameMatches === false) {
      findings.push({
        title: "TLS certificate does not match the hostname",
        affected: { url },
        severity: "high",
        reproduction: [`Inspect the certificate presented by ${url}.`],
        remediation: "Issue a certificate with the correct SAN/CN for the hostname.",
        details: certificate.subject ?? "Hostname mismatch.",
      });
    }
    if (
      certificate.signatureAlgorithm !== undefined &&
      /sha-?1\b/i.test(certificate.signatureAlgorithm)
    ) {
      findings.push({
        title: "TLS certificate uses a SHA-1 signature",
        affected: { url },
        severity: "medium",
        reproduction: [`Inspect the certificate presented by ${url}.`],
        remediation: "Reissue the certificate with SHA-256 or stronger.",
        details: `Signature algorithm: ${certificate.signatureAlgorithm}`,
      });
    }
    if (certificate.keyBits !== undefined) {
      const algorithm = certificate.keyAlgorithm?.toLowerCase() ?? "";
      const minimum = algorithm.includes("ec") ? 256 : 2048;
      if (certificate.keyBits < minimum) {
        findings.push({
          title: "TLS certificate key is too small",
          affected: { url },
          severity: "medium",
          reproduction: [`Inspect the certificate presented by ${url}.`],
          remediation: `Use at least ${minimum}-bit keys.`,
          details: `Key: ${certificate.keyAlgorithm ?? "unknown"} ${certificate.keyBits} bits.`,
        });
      }
    }
  }

  // HSTS is reported here only for a real TLS observation, so the common
  // HTTP-only path does not duplicate the security-headers finding.
  const hasHandshakeFacts =
    observation.protocol !== undefined || observation.cipher !== undefined;
  let isHttps: boolean;
  try {
    isHttps = new URL(url).protocol === "https:";
  } catch {
    isHttps = false;
  }
  if (isHttps && hasHandshakeFacts && headerValue(observation.headers, "strict-transport-security") === undefined) {
    findings.push({
      title: "Strict-Transport-Security header is missing",
      affected: { url },
      severity: "medium",
      reproduction: [`Send a GET request to ${url} and inspect the response headers.`],
      remediation: "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
      details: "HSTS was absent from the HTTPS response.",
    });
  }

  return findings;
}

export const tlsCheck: Check = {
  metadata: {
    id: "tls",
    toolName: "check_tls",
    title: "TLS protocol, cipher, and certificate posture",
    description:
      "Checks TLS version, cipher strength, certificate validity, hostname match, key size, and HSTS for approved TLS observations.",
    category: "A04",
    categories: ["A04"],
    cwe: "CWE-326",
    relatedCwes: ["CWE-327", "CWE-295", "CWE-296"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 1,
    references: [
      "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
      "https://cwe.mitre.org/data/definitions/326.html",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const primary = await fetchPrimary(ctx, input);
    if (primary.error !== undefined) {
      return checkResult(ctx, [], [], primary.error);
    }
    if (primary.response === undefined || primary.request === undefined) {
      return checkResult(ctx, [], [], "tls check received no response");
    }
    const evidence: EvidenceRef[] = [];
    const captured = await captureResponse(ctx, primary.request, primary.response);
    if (captured !== undefined) evidence.push(captured);

    const tlsRecord = readOptionRecord(input.options, "tls");
    const certificateRecord = tlsRecord
      ? readOptionRecord(tlsRecord, "certificate")
      : undefined;
    const candidates = analyzeTls(
      {
        url: primary.response.url,
        headers: primary.response.headers,
        protocol: tlsRecord ? readRecordString(tlsRecord, "protocol") : undefined,
        cipher: tlsRecord ? readRecordString(tlsRecord, "cipher") : undefined,
        certificate: parseTlsCertificate(certificateRecord),
      },
      ctx.now(),
    );
    return checkResult(ctx, materialize(tlsCheck.metadata, candidates, evidence), evidence);
  },
};
