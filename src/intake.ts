import { readFile } from "node:fs/promises";
import { readEnv } from "./config.js";
import { validateAuthorization } from "./guardrails/authorization.js";
import type { AuthorizationStatus } from "./guardrails/authorization.js";
import { parseScope } from "./model/scope.js";
import type { Scope } from "./model/scope.js";

export interface IntakeSuccess {
  ok: true;
  scope: Scope;
  authorization: AuthorizationStatus;
}

export interface IntakeFailure {
  ok: false;
  errors: string[];
  authorization?: AuthorizationStatus;
}

export type IntakeResult = IntakeSuccess | IntakeFailure;

/**
 * Load and validate a scope document. This performs no network I/O: a scope
 * that fails validation is refused before any request exists.
 */
export async function intake(
  scopePath: string,
  now: Date = new Date(),
  env: (name: string) => string | undefined = readEnv,
): Promise<IntakeResult> {
  let raw: string;
  try {
    raw = await readFile(scopePath, "utf8");
  } catch (err) {
    return {
      ok: false,
      errors: [`cannot read scope file: ${(err as NodeJS.ErrnoException).code ?? "unknown error"}`],
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return { ok: false, errors: ["scope file is not valid JSON"] };
  }

  const parsed = parseScope(json);
  if (!parsed.ok) return { ok: false, errors: parsed.errors };

  const scope = parsed.value;
  const authorization = validateAuthorization(scope.authorization, now, env);
  if (!authorization.ok) {
    return {
      ok: false,
      errors: [authorization.reason ?? "authorization is invalid"],
      authorization,
    };
  }
  return { ok: true, scope, authorization };
}
