import { isIP } from "node:net";

/** Scope document types and validation. This module has no I/O. */

export const SUPPORTED_SCOPE_VERSION = 1;

export const HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

export const READ_ONLY_METHODS: readonly HttpMethod[] = ["GET", "HEAD", "OPTIONS"];

export const OWASP_CATEGORIES = [
  "A01",
  "A02",
  "A03",
  "A04",
  "A05",
  "A06",
  "A07",
  "A08",
  "A09",
  "A10",
] as const;
export type OwaspCategory = (typeof OWASP_CATEGORIES)[number];

/** Official OWASP Top 10:2025 names, used verbatim in prompts and reports. */
export const OWASP_CATEGORY_NAMES: Record<OwaspCategory, string> = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A06: "Insecure Design",
  A07: "Authentication Failures",
  A08: "Software or Data Integrity Failures",
  A09: "Security Logging and Alerting Failures",
  A10: "Mishandling of Exceptional Conditions",
};

export type Scheme = "http" | "https";

export interface Authorization {
  reference: string;
  owner: string;
  issuedBy?: string;
  /** ISO 8601 date-time. */
  validFrom: string;
  /** ISO 8601 date-time. */
  validUntil: string;
  /** Literal token or `env:NAME` referencing an environment variable. */
  token: string;
}

export interface Target {
  /** Exact host, IP literal, or `*.example.com` wildcard. */
  host: string;
  scheme?: Scheme;
  port?: number;
  /** Path prefixes. Empty or omitted means all paths. */
  paths?: string[];
  /** Allowed methods. Empty or omitted means read-only methods. */
  methods?: HttpMethod[];
}

export interface HostDeny {
  host: string;
  paths?: string[];
}

export interface CidrDeny {
  cidr: string;
}

export type DenyEntry = HostDeny | CidrDeny;

export type StateChangingMode = "deny" | "approve" | "allow";

export interface StateChangingPolicy {
  mode: StateChangingMode;
  /** Entries look like `POST /api/contact`. */
  allow?: string[];
}

export interface ScopePolicy {
  maxRequests?: number;
  maxDurationMinutes?: number;
  maxConcurrentPerHost?: number;
  requestsPerSecondPerHost?: number;
  maxBodyBytes?: number;
  maxRedirects?: number;
  followExternalRedirects?: boolean;
  maxModelTurns?: number;
  maxFindingsPerCategory?: number;
}

export interface Scope {
  version: 1;
  name: string;
  authorization: Authorization;
  targets: Target[];
  deny: DenyEntry[];
  testClasses: OwaspCategory[];
  readOnly: boolean;
  stateChanging?: StateChangingPolicy;
  policy?: ScopePolicy;
}

export type ParseResult<T> = { ok: true; value: T } | { ok: false; errors: string[] };

export interface Cidr {
  raw: string;
  family: 4 | 6;
  address: bigint;
  prefix: number;
  mask: bigint;
}

export function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  return host.split(".").every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

export function isValidHostPattern(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, "");
  if (normalized.length === 0) return false;
  if (normalized.startsWith("*.")) return isValidHostname(normalized.slice(2));
  return isValidHostname(normalized) || isIP(normalized) !== 0;
}

export function parseCidr(input: string): Cidr | undefined {
  const slash = input.indexOf("/");
  if (slash <= 0 || slash === input.length - 1) return undefined;
  const addressText = input.slice(0, slash);
  const prefixText = input.slice(slash + 1);
  if (!/^\d+$/.test(prefixText)) return undefined;
  const family = isIP(addressText);
  if (family !== 4 && family !== 6) return undefined;
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (prefix < 0 || prefix > bits) return undefined;
  const address = ipToBigInt(addressText);
  if (address === undefined) return undefined;
  const mask = prefix === 0 ? 0n : (1n << BigInt(bits)) - (1n << BigInt(bits - prefix));
  return { raw: input, family, address, prefix, mask };
}

export function ipToBigInt(ip: string): bigint | undefined {
  const family = isIP(ip);
  if (family === 4) {
    const parts = ip.split(".");
    if (parts.length !== 4) return undefined;
    let value = 0n;
    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) return undefined;
      const octet = Number(part);
      if (octet > 255) return undefined;
      value = (value << 8n) | BigInt(octet);
    }
    return value;
  }
  if (family === 6) {
    const normalized = normalizeIpv6(ip);
    if (normalized === undefined) return undefined;
    const halves = normalized.split("::");
    if (halves.length > 2) return undefined;
    const left = halves[0] === "" ? [] : halves[0].split(":");
    const right = halves.length === 2 ? (halves[1] === "" ? [] : halves[1].split(":")) : [];
    const missing = halves.length === 2 ? 8 - left.length - right.length : left.length;
    if (missing < 0 || missing > 8) return undefined;
    if (halves.length !== 2 && left.length !== 8) return undefined;
    const groups = [
      ...left,
      ...Array.from({ length: halves.length === 2 ? missing : 0 }, () => "0"),
      ...right,
    ];
    if (groups.length !== 8) return undefined;
    let value = 0n;
    for (const group of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return undefined;
      value = (value << 16n) | BigInt(parseInt(group, 16));
    }
    return value;
  }
  return undefined;
}

function normalizeIpv6(ip: string): string | undefined {
  const lastColon = ip.lastIndexOf(":");
  if (lastColon >= 0 && ip.indexOf(".", lastColon) >= 0) {
    const v4 = ip.slice(lastColon + 1);
    if (isIP(v4) !== 4) return undefined;
    const v4Value = ipToBigInt(v4);
    if (v4Value === undefined) return undefined;
    const high = (v4Value >> 16n).toString(16);
    const low = (v4Value & 0xffffn).toString(16);
    return `${ip.slice(0, lastColon + 1)}${high}:${low}`;
  }
  return ip;
}

export function cidrContains(cidr: Cidr, ip: string): boolean {
  if (isIP(ip) !== cidr.family) return false;
  const address = ipToBigInt(ip);
  if (address === undefined) return false;
  return (address & cidr.mask) === (cidr.address & cidr.mask);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readNonEmptyString(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string | undefined {
  const value = obj[key];
  if (typeof value !== "string") {
    errors.push(`${label} must be a string`);
    return undefined;
  }
  if (value.trim().length === 0) {
    errors.push(`${label} must not be empty`);
    return undefined;
  }
  return value;
}

function readOptionalString(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    errors.push(`${label} must be a string`);
    return undefined;
  }
  return value;
}

function readBoolean(
  obj: Record<string, unknown>,
  key: string,
  fallback: boolean | undefined,
  errors: string[],
  label: string = key,
): boolean | undefined {
  const value = obj[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    errors.push(`${label} must be a boolean`);
    return undefined;
  }
  return value;
}

function readPositiveInt(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): number | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    errors.push(`${label} must be a positive integer`);
    return undefined;
  }
  return value;
}

function readEnum<T extends string>(
  obj: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
  errors: string[],
  label: string = key,
): T | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    errors.push(`${label} must be one of: ${allowed.join(", ")}`);
    return undefined;
  }
  return value as T;
}

function readStringArray(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string[] | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    errors.push(`${label} must be an array of strings`);
    return undefined;
  }
  return value as string[];
}

function readPaths(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string[] | undefined {
  const paths = readStringArray(obj, key, errors, label);
  if (paths === undefined) return undefined;
  for (let i = 0; i < paths.length; i++) {
    if (!paths[i].startsWith("/")) {
      errors.push(`${label}[${i}] must start with "/"`);
      return undefined;
    }
  }
  return paths;
}

function readMethods(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): HttpMethod[] | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== "string" || !HTTP_METHODS.includes(item as HttpMethod))
  ) {
    errors.push(`${label} must be a non-empty array of HTTP methods`);
    return undefined;
  }
  return value as HttpMethod[];
}

function readIsoDate(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string | undefined {
  const value = obj[key];
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    errors.push(`${label} must be an ISO 8601 date-time`);
    return undefined;
  }
  return value;
}

function readToken(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): string | undefined {
  const token = readNonEmptyString(obj, key, errors, label);
  if (token === undefined) return undefined;
  if (token.startsWith("env:")) {
    const name = token.slice(4);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      errors.push(`${label} has an invalid environment variable name`);
    }
  }
  return token;
}

function readScheme(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): Scheme | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (value !== "http" && value !== "https") {
    errors.push(`${label} must be "http" or "https"`);
    return undefined;
  }
  return value;
}

function readPort(
  obj: Record<string, unknown>,
  key: string,
  errors: string[],
  label: string = key,
): number | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 65535) {
    errors.push(`${label} must be an integer between 1 and 65535`);
    return undefined;
  }
  return value;
}

function parseAuthorization(input: unknown, errors: string[]): Authorization | undefined {
  if (!isRecord(input)) {
    errors.push("authorization must be an object");
    return undefined;
  }
  const reference = readNonEmptyString(input, "reference", errors, "authorization.reference");
  const owner = readNonEmptyString(input, "owner", errors, "authorization.owner");
  const issuedBy = readOptionalString(input, "issuedBy", errors, "authorization.issuedBy");
  const validFrom = readIsoDate(input, "validFrom", errors, "authorization.validFrom");
  const validUntil = readIsoDate(input, "validUntil", errors, "authorization.validUntil");
  const token = readToken(input, "token", errors, "authorization.token");
  if (
    validFrom !== undefined &&
    validUntil !== undefined &&
    Date.parse(validUntil) <= Date.parse(validFrom)
  ) {
    errors.push("authorization.validUntil must be after authorization.validFrom");
  }
  if (
    reference === undefined ||
    owner === undefined ||
    validFrom === undefined ||
    validUntil === undefined ||
    token === undefined
  ) {
    return undefined;
  }
  return { reference, owner, issuedBy, validFrom, validUntil, token };
}

function parseTargets(input: unknown, errors: string[]): Target[] | undefined {
  if (!Array.isArray(input)) {
    errors.push("targets must be an array");
    return undefined;
  }
  if (input.length === 0) {
    errors.push("targets must not be empty");
    return undefined;
  }
  const targets: Target[] = [];
  for (let i = 0; i < input.length; i++) {
    const item = input[i];
    if (!isRecord(item)) {
      errors.push(`targets[${i}] must be an object`);
      continue;
    }
    const host = readNonEmptyString(item, "host", errors, `targets[${i}].host`);
    if (host === undefined) continue;
    if (!isValidHostPattern(host)) {
      errors.push(`targets[${i}].host is not a valid host or IP address`);
      continue;
    }
    const scheme = readScheme(item, "scheme", errors, `targets[${i}].scheme`);
    const port = readPort(item, "port", errors, `targets[${i}].port`);
    const paths = readPaths(item, "paths", errors, `targets[${i}].paths`);
    const methods = readMethods(item, "methods", errors, `targets[${i}].methods`);
    if (scheme === undefined && errors.some((e) => e.startsWith(`targets[${i}].scheme`))) {
      continue;
    }
    if (port === undefined && errors.some((e) => e.startsWith(`targets[${i}].port`))) {
      continue;
    }
    if (paths === undefined && errors.some((e) => e.startsWith(`targets[${i}].paths`))) {
      continue;
    }
    if (methods === undefined && errors.some((e) => e.startsWith(`targets[${i}].methods`))) {
      continue;
    }
    targets.push({ host, scheme, port, paths, methods });
  }
  if (targets.length === 0) {
    errors.push("targets must contain at least one valid target");
    return undefined;
  }
  return targets;
}

function parseDeny(input: unknown, errors: string[]): DenyEntry[] | undefined {
  if (!Array.isArray(input)) {
    errors.push("deny must be an array");
    return undefined;
  }
  const entries: DenyEntry[] = [];
  for (let i = 0; i < input.length; i++) {
    const item = input[i];
    if (!isRecord(item)) {
      errors.push(`deny[${i}] must be an object`);
      continue;
    }
    if (typeof item.cidr === "string") {
      const cidr = parseCidr(item.cidr);
      if (cidr === undefined) {
        errors.push(`deny[${i}].cidr is not a valid CIDR`);
        continue;
      }
      entries.push({ cidr: item.cidr });
      continue;
    }
    if (typeof item.host === "string") {
      if (!isValidHostPattern(item.host)) {
        errors.push(`deny[${i}].host is not a valid host or IP address`);
        continue;
      }
      const paths = readPaths(item, "paths", errors, `deny[${i}].paths`);
      entries.push({ host: item.host, paths });
      continue;
    }
    errors.push(`deny[${i}] must contain either host or cidr`);
  }
  return entries;
}

function isOwaspCategory(value: string): value is OwaspCategory {
  return (OWASP_CATEGORIES as readonly string[]).includes(value);
}

function parseTestClasses(input: unknown, errors: string[]): OwaspCategory[] | undefined {
  if (input === undefined) return [...OWASP_CATEGORIES];
  if (!Array.isArray(input) || input.length === 0) {
    errors.push("testClasses must be a non-empty array");
    return undefined;
  }
  const classes: OwaspCategory[] = [];
  for (let i = 0; i < input.length; i++) {
    const value = input[i];
    if (typeof value !== "string" || !isOwaspCategory(value)) {
      errors.push(`testClasses[${i}] is not a valid OWASP Top 10:2025 category`);
      continue;
    }
    classes.push(value);
  }
  if (classes.length === 0) {
    errors.push("testClasses must contain at least one valid category");
    return undefined;
  }
  return classes;
}

function parseStateChanging(input: unknown, errors: string[]): StateChangingPolicy | undefined {
  if (input === undefined) return undefined;
  if (!isRecord(input)) {
    errors.push("stateChanging must be an object");
    return undefined;
  }
  const mode =
    readEnum(input, "mode", ["deny", "approve", "allow"] as const, errors, "stateChanging.mode") ??
    "deny";
  const allow = readStringArray(input, "allow", errors, "stateChanging.allow");
  if (allow !== undefined) {
    for (let i = 0; i < allow.length; i++) {
      if (!/^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE) \/.*$/.test(allow[i])) {
        errors.push(`stateChanging.allow[${i}] must look like "METHOD /path"`);
      }
    }
  }
  return { mode, allow };
}

function parsePolicy(input: unknown, errors: string[]): ScopePolicy | undefined {
  if (input === undefined) return undefined;
  if (!isRecord(input)) {
    errors.push("policy must be an object");
    return undefined;
  }
  const policy: ScopePolicy = {};
  const maxRequests = readPositiveInt(input, "maxRequests", errors, "policy.maxRequests");
  if (maxRequests !== undefined) policy.maxRequests = maxRequests;
  const maxDurationMinutes = readPositiveInt(
    input,
    "maxDurationMinutes",
    errors,
    "policy.maxDurationMinutes",
  );
  if (maxDurationMinutes !== undefined) policy.maxDurationMinutes = maxDurationMinutes;
  const maxConcurrentPerHost = readPositiveInt(
    input,
    "maxConcurrentPerHost",
    errors,
    "policy.maxConcurrentPerHost",
  );
  if (maxConcurrentPerHost !== undefined) policy.maxConcurrentPerHost = maxConcurrentPerHost;
  const requestsPerSecondPerHost = readPositiveInt(
    input,
    "requestsPerSecondPerHost",
    errors,
    "policy.requestsPerSecondPerHost",
  );
  if (requestsPerSecondPerHost !== undefined) {
    policy.requestsPerSecondPerHost = requestsPerSecondPerHost;
  }
  const maxBodyBytes = readPositiveInt(input, "maxBodyBytes", errors, "policy.maxBodyBytes");
  if (maxBodyBytes !== undefined) policy.maxBodyBytes = maxBodyBytes;
  const maxRedirects = readPositiveInt(input, "maxRedirects", errors, "policy.maxRedirects");
  if (maxRedirects !== undefined) policy.maxRedirects = maxRedirects;
  const maxModelTurns = readPositiveInt(input, "maxModelTurns", errors, "policy.maxModelTurns");
  if (maxModelTurns !== undefined) policy.maxModelTurns = maxModelTurns;
  const maxFindingsPerCategory = readPositiveInt(
    input,
    "maxFindingsPerCategory",
    errors,
    "policy.maxFindingsPerCategory",
  );
  if (maxFindingsPerCategory !== undefined) {
    policy.maxFindingsPerCategory = maxFindingsPerCategory;
  }
  const followExternalRedirects = readBoolean(
    input,
    "followExternalRedirects",
    undefined,
    errors,
    "policy.followExternalRedirects",
  );
  if (followExternalRedirects !== undefined) {
    policy.followExternalRedirects = followExternalRedirects;
  }
  return policy;
}

export function parseScope(input: unknown): ParseResult<Scope> {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["scope must be a JSON object"] };
  }
  if (input.version !== SUPPORTED_SCOPE_VERSION) {
    errors.push(`unsupported scope version (expected ${SUPPORTED_SCOPE_VERSION})`);
  }
  const name = readNonEmptyString(input, "name", errors);
  const authorization = parseAuthorization(input.authorization, errors);
  const targets = parseTargets(input.targets, errors);
  const deny = parseDeny(input.deny, errors);
  const testClasses = parseTestClasses(input.testClasses, errors);
  const readOnly = readBoolean(input, "readOnly", true, errors);
  const stateChanging = parseStateChanging(input.stateChanging, errors);
  const policy = parsePolicy(input.policy, errors);

  if (
    errors.length > 0 ||
    name === undefined ||
    authorization === undefined ||
    targets === undefined ||
    deny === undefined ||
    testClasses === undefined ||
    readOnly === undefined
  ) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    value: {
      version: SUPPORTED_SCOPE_VERSION,
      name,
      authorization,
      targets,
      deny,
      testClasses,
      readOnly,
      stateChanging,
      policy,
    },
  };
}
