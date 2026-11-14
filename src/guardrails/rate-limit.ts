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

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
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

  get remainingGlobal(): number {
    return Math.max(0, this.maxRequests - this.used);
  }
}
