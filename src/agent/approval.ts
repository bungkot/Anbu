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

/**
 * Core-slice default: deny everything. The interactive provider (and the
 * `--auto-approve` flag) arrives with the HITL follow-up.
 */
export const denyAllApprovals: ApprovalProvider = {
  async approve(): Promise<boolean> {
    return false;
  },
};
