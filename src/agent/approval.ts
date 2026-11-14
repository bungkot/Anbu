import { createInterface } from "node:readline/promises";

/** Human-in-the-loop approval gate for state-changing or destructive actions. */
export interface ApprovalRequest {
  /** Stable action identifier, for example `run_check:upload`. */
  action: string;
  method: string;
  url: string;
  reason: string;
}

export interface ApprovalProvider {
  approve(request: ApprovalRequest): Promise<boolean>;
}

/** How the run resolves state-changing approval requests. */
export type ApprovalMode = "deny-all" | "auto-approve" | "interactive";

/**
 * Core-slice default: deny everything. The auto-approve flag and the
 * interactive provider are explicit operator choices; neither can bypass the
 * scope or policy guardrails, which reject disallowed requests regardless.
 */
export const denyAllApprovals: ApprovalProvider = {
  async approve(): Promise<boolean> {
    return false;
  },
};

/** Grants every request. Guardrails still enforce read-only scope and policy. */
export const autoApprove: ApprovalProvider = {
  async approve(): Promise<boolean> {
    return true;
  },
};

export interface InteractiveApprovalOptions {
  /**
   * Decide one approval request. Defaults to a stdin prompt that accepts
   * `y`/`yes`; any other answer, EOF, or read error denies the request.
   */
  ask?: (request: ApprovalRequest) => boolean | Promise<boolean>;
}

/** Parse a yes/no answer. Only an explicit affirmative approves. */
export function isApprovedAnswer(answer: string): boolean {
  return /^\s*y(es)?\s*$/i.test(answer);
}

function formatPrompt(request: ApprovalRequest): string {
  return [
    "State-changing action requires human approval:",
    `  action : ${request.action}`,
    `  method : ${request.method}`,
    `  url    : ${request.url}`,
    `  reason : ${request.reason}`,
    "Approve? [y/N] ",
  ].join("\n");
}

/**
 * Interactive approval provider for an operator running a state-changing test.
 * Fails closed: a missing answer, EOF, or a read error denies the request.
 */
export function interactiveApprovals(
  options: InteractiveApprovalOptions = {},
): ApprovalProvider {
  let rl: ReturnType<typeof createInterface> | undefined;

  async function defaultAsk(request: ApprovalRequest): Promise<boolean> {
    try {
      rl ??= createInterface({ input: process.stdin, output: process.stdout });
      const answer = await rl.question(formatPrompt(request));
      return isApprovedAnswer(answer);
    } catch {
      return false;
    }
  }

  const ask = options.ask ?? defaultAsk;
  return {
    async approve(request) {
      return ask(request);
    },
  };
}
