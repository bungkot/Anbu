import type { OwaspCategory } from "../../model/scope.js";
import type { Check, CheckMetadata } from "./types.js";
import { authzMethodsCheck } from "./authz-methods.js";
import { commandInjectionCheck } from "./command-injection.js";
import { corsCheck } from "./cors.js";
import { defaultCredentialsCheck } from "./default-credentials.js";
import { dependenciesCheck } from "./dependencies.js";
import { deserializationCheck } from "./deserialization.js";
import { errorHandlingCheck } from "./error-handling.js";
import { forceBrowsingCheck } from "./force-browsing.js";
import { idorCheck } from "./idor.js";
import { jwtCheck } from "./jwt.js";
import { loggingCheck } from "./logging.js";
import { passwordHashCheck } from "./password-hash.js";
import { pathTraversalCheck } from "./path-traversal.js";
import { rateLimitCheck } from "./rate-limit.js";
import { securityHeadersCheck } from "./security-headers.js";
import { sqliCheck } from "./sqli.js";
import { tlsCheck } from "./tls.js";
import { uploadCheck } from "./upload.js";
import { xssCheck } from "./xss.js";
import { xxeCheck } from "./xxe.js";

export {
  authzMethodsCheck,
  commandInjectionCheck,
  corsCheck,
  defaultCredentialsCheck,
  dependenciesCheck,
  deserializationCheck,
  errorHandlingCheck,
  forceBrowsingCheck,
  idorCheck,
  jwtCheck,
  loggingCheck,
  passwordHashCheck,
  pathTraversalCheck,
  rateLimitCheck,
  securityHeadersCheck,
  sqliCheck,
  tlsCheck,
  uploadCheck,
  xssCheck,
  xxeCheck,
};

/** Every deterministic check, in registry order. */
export const CHECKS: readonly Check[] = [
  securityHeadersCheck,
  tlsCheck,
  passwordHashCheck,
  dependenciesCheck,
  sqliCheck,
  xssCheck,
  commandInjectionCheck,
  xxeCheck,
  pathTraversalCheck,
  idorCheck,
  forceBrowsingCheck,
  corsCheck,
  jwtCheck,
  authzMethodsCheck,
  defaultCredentialsCheck,
  errorHandlingCheck,
  loggingCheck,
  deserializationCheck,
  uploadCheck,
  rateLimitCheck,
];

/** All registered check metadata, in registry order. */
export function listChecks(): CheckMetadata[] {
  return CHECKS.map((check) => check.metadata);
}

/** Look a check up by its stable id (for example `sqli`). */
export function getCheck(id: string): Check | undefined {
  return CHECKS.find((check) => check.metadata.id === id);
}

/** Look a check up by its agent-facing tool name (for example `check_sqli`). */
export function getCheckByToolName(toolName: string): Check | undefined {
  return CHECKS.find((check) => check.metadata.toolName === toolName);
}

/** Checks that contribute evidence to an OWASP category. */
export function checksForCategory(category: OwaspCategory): Check[] {
  return CHECKS.filter((check) => check.metadata.categories.includes(category));
}

/** Checks that may run without a human approval gate. */
export function readOnlyChecks(): Check[] {
  return CHECKS.filter((check) => check.metadata.readOnly);
}

/** Checks that must not run without an explicit human approval gate. */
export function approvalRequiredChecks(): Check[] {
  return CHECKS.filter((check) => check.metadata.requiresApproval);
}

/**
 * Validate registry invariants. Returns a list of problems; an empty list
 * means the registry is consistent. The unit suite runs this on every change.
 */
export function validateCheckRegistry(): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  const toolNames = new Set<string>();

  for (const check of CHECKS) {
    const { metadata } = check;
    if (ids.has(metadata.id)) problems.push(`duplicate check id: ${metadata.id}`);
    ids.add(metadata.id);
    if (toolNames.has(metadata.toolName)) {
      problems.push(`duplicate tool name: ${metadata.toolName}`);
    }
    toolNames.add(metadata.toolName);
    if (metadata.maxRequests < 0) {
      problems.push(`${metadata.id}: maxRequests must not be negative`);
    }
    if (!metadata.readOnly && !metadata.requiresApproval) {
      problems.push(`${metadata.id}: state-changing check must require approval`);
    }
    if (metadata.readOnly && metadata.requiresApproval) {
      problems.push(`${metadata.id}: read-only check must not require approval`);
    }
    if (metadata.categories.length === 0) {
      problems.push(`${metadata.id}: at least one category is required`);
    }
    if (!metadata.categories.includes(metadata.category)) {
      problems.push(`${metadata.id}: primary category is not in categories`);
    }
  }

  return problems;
}
