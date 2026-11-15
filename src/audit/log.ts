import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { ApprovalMode } from "../agent/approval.js";

export interface AuditDetails {
  decision?: "allow" | "deny";
  reason?: string;
  method?: string;
  target?: string;
  evidenceId?: string;
  /** Deterministic check that produced the entry. */
  check?: string;
  /** Number of findings the check produced. */
  findings?: number;
  /** Number of HTTP requests the check issued. */
  requests?: number;
  /** OWASP category of a finding. */
  category?: string;
  /** HTTP status of an observed response. */
  status?: number;
  /** Scope name for run lifecycle entries. */
  scope?: string;
  /** Authorization reference for run lifecycle entries. */
  authorization?: string;
  /** Target hosts for run lifecycle entries. */
  targets?: string[];
  /** Stop reason for run lifecycle entries. */
  stopReason?: string;
  /** How state-changing approvals were resolved for the run. */
  approvalMode?: ApprovalMode;
  /** Milliseconds a guardrail spent waiting for a per-host rate-limit token. */
  waitedMs?: number;
}

export interface AuditEntry {
  seq: number;
  timestamp: string;
  runId: string;
  event: string;
  decision?: "allow" | "deny";
  reason?: string;
  method?: string;
  target?: string;
  evidenceId?: string;
  approvalMode?: ApprovalMode;
  waitedMs?: number;
  prevHash: string;
  hash: string;
}

export interface AuditVerifyResult {
  ok: boolean;
  entries: number;
  brokenAt?: number;
  reason?: string;
}

const GENESIS_HASH = "0".repeat(64);

function computeHash(prevHash: string, body: object): string {
  return createHash("sha256").update(prevHash).update(JSON.stringify(body)).digest("hex");
}

/**
 * Append-only, hash-chained audit log. Each entry commits to the previous
 * entry's hash, so modifying or removing a line breaks verification.
 */
export class AuditLog {
  private readonly filePath: string;
  private readonly runId: string;
  private entries: AuditEntry[] = [];
  private prevHash = GENESIS_HASH;
  private seq = 0;
  private loaded = false;

  constructor(filePath: string, runId: string) {
    this.filePath = filePath;
    this.runId = runId;
  }

  async load(): Promise<void> {
    if (this.loaded) return;
    let text: string;
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        this.loaded = true;
        return;
      }
      throw err;
    }
    for (const line of text.split(/\r?\n/)) {
      if (line.trim().length === 0) continue;
      const entry = JSON.parse(line) as AuditEntry;
      this.entries.push(entry);
      this.prevHash = entry.hash;
      this.seq = Math.max(this.seq, entry.seq);
    }
    this.loaded = true;
  }

  async append(event: string, details: AuditDetails = {}): Promise<AuditEntry> {
    await this.load();
    this.seq += 1;
    const body: Omit<AuditEntry, "prevHash" | "hash"> = {
      seq: this.seq,
      timestamp: new Date().toISOString(),
      runId: this.runId,
      event,
      ...details,
    };
    const hash = computeHash(this.prevHash, body);
    const entry: AuditEntry = { ...body, prevHash: this.prevHash, hash };
    await mkdir(dirname(this.filePath), { recursive: true });
    await appendFile(this.filePath, `${JSON.stringify(entry)}\n`, "utf8");
    this.entries.push(entry);
    this.prevHash = hash;
    return entry;
  }

  async verify(): Promise<AuditVerifyResult> {
    await this.load();
    let previous = GENESIS_HASH;
    for (const entry of this.entries) {
      if (entry.prevHash !== previous) {
        return {
          ok: false,
          entries: this.entries.length,
          brokenAt: entry.seq,
          reason: "previous hash mismatch",
        };
      }
      const { hash, prevHash, ...body } = entry;
      const expected = computeHash(prevHash, body);
      if (hash !== expected) {
        return {
          ok: false,
          entries: this.entries.length,
          brokenAt: entry.seq,
          reason: "entry hash mismatch",
        };
      }
      previous = hash;
    }
    return { ok: true, entries: this.entries.length };
  }

  list(): readonly AuditEntry[] {
    return this.entries;
  }
}
