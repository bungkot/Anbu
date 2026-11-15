export interface RateLimitOptions {
  /** Sustained requests per second allowed per host. Also the burst capacity. */
  requestsPerSecondPerHost: number;
  /** Global request budget for the whole run. */
  maxRequests: number;
}

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  /** Milliseconds spent waiting for a per-host token; undefined when not paced. */
  waitedMs?: number;
}

export interface AcquireOptions {
  /**
   * Maximum time to wait for a token before denying. A value of zero (or less)
   * restores the original deny-immediately behaviour.
   */
  maxWaitMs: number;
  /** Injectable timer for deterministic tests. Defaults to a real timer. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Token bucket per host plus a global request budget. Guardrails call
 * `tryAcquire` before a request; a denied request is never sent.
 */
export class RateLimiter {
  private readonly rate: number;
  private readonly maxRequests: number;
  private used = 0;
  private readonly buckets = new Map<string, Bucket>();

  constructor(options: RateLimitOptions) {
    this.rate = options.requestsPerSecondPerHost;
    this.maxRequests = options.maxRequests;
  }

  tryAcquire(host: string, nowMs: number = Date.now()): RateLimitDecision {
    if (this.used >= this.maxRequests) {
      return { allowed: false, reason: "global request budget exhausted" };
    }
    const bucket = this.buckets.get(host) ?? {
      tokens: this.rate,
      lastRefillMs: nowMs,
    };
    const elapsedSeconds = Math.max(0, nowMs - bucket.lastRefillMs) / 1000;
    bucket.tokens = Math.min(this.rate, bucket.tokens + elapsedSeconds * this.rate);
    bucket.lastRefillMs = nowMs;
    if (bucket.tokens < 1) {
      this.buckets.set(host, bucket);
      return { allowed: false, reason: `per-host rate limit exceeded for ${host}` };
    }
    bucket.tokens -= 1;
    this.buckets.set(host, bucket);
    this.used += 1;
    return { allowed: true };
  }

  /**
   * Acquire a token, waiting up to `maxWaitMs` for one to refill. Per-host
   * throttling is transient, so callers pace themselves; the global budget is a
   * hard cap and is never waited out.
   */
  async acquire(host: string, nowMs: number, options: AcquireOptions): Promise<RateLimitDecision> {
    const maxWaitMs = Math.max(0, options.maxWaitMs);
    if (maxWaitMs === 0) return { ...this.tryAcquire(host, nowMs), waitedMs: 0 };

    let waitedMs = 0;
    for (;;) {
      const decision = this.tryAcquire(host, nowMs);
      if (decision.allowed) return { ...decision, waitedMs };
      if (!decision.reason?.includes("per-host")) return { ...decision, waitedMs };

      const neededMs = this.msUntilNextToken(host);
      if (!Number.isFinite(neededMs) || waitedMs + neededMs > maxWaitMs) {
        return { allowed: false, reason: decision.reason, waitedMs };
      }
      await (options.sleep ?? defaultSleep)(neededMs);
      waitedMs += neededMs;
      nowMs += neededMs;
    }
  }

  /** Milliseconds until the host bucket holds at least one token. */
  private msUntilNextToken(host: string): number {
    const bucket = this.buckets.get(host);
    if (bucket === undefined || bucket.tokens >= 1) return 0;
    if (this.rate <= 0) return Number.POSITIVE_INFINITY;
    return Math.ceil(((1 - bucket.tokens) / this.rate) * 1000);
  }

  get remainingGlobal(): number {
    return Math.max(0, this.maxRequests - this.used);
  }
}
