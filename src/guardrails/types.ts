import type { Target } from "../model/scope.js";

/** A request that is about to leave the process. */
export interface GuardRequest {
  method: string;
  url: string;
  body?: string | Uint8Array;
  /** Precomputed body size in bytes; overrides `body` when present. */
  bodyBytes?: number;
}

export type GuardDecision =
  | { allowed: true; target?: Target }
  | { allowed: false; reason: string; requiresApproval?: boolean };
