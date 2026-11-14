import type { AuditLog } from "./audit/log.js";
import type { RateLimiter } from "./guardrails/rate-limit.js";
import type { Scope, Target } from "./model/scope.js";
import { Crawler } from "./tools/crawl.js";
import type {
  CrawledAsset,
  CrawledBlock,
  CrawledForm,
  CrawlResult,
  TechnologyMarker,
} from "./tools/crawl.js";
import { GuardedHttpClient } from "./tools/http.js";

export interface ReconOptions {
  scope: Scope;
  /** Explicit start URLs. Derived from the scope targets when omitted. */
  startUrls?: string[];
  maxDepth?: number;
  maxUrls?: number;
  /** Follow discovered links even when they leave the scope. Default true. */
  stayInScope?: boolean;
  rateLimiter: RateLimiter;
  audit: AuditLog;
  fetchFn?: typeof fetch;
  env?: (name: string) => string | undefined;
  maxResponseBodyBytes?: number;
}

export interface AttackSurfaceSummary {
  targets: string[];
  startUrls: string[];
  urls: string[];
  forms: CrawledForm[];
  assets: CrawledAsset[];
  technologies: TechnologyMarker[];
  blocked: CrawledBlock[];
  requests: number;
  truncated: boolean;
  maxDepth: number;
  maxUrls: number;
}

export interface ReconResult {
  ok: boolean;
  error?: string;
  scopeName: string;
  summary?: AttackSurfaceSummary;
  crawls: CrawlResult[];
}

function targetOrigin(target: Target): string {
  const scheme = target.scheme ?? (target.port === 80 ? "http" : "https");
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = target.port === undefined || target.port === defaultPort ? "" : `:${target.port}`;
  return `${scheme}://${target.host}${port}`;
}

function isConcreteHost(host: string): boolean {
  return !host.includes("*");
}

/** One start URL per concrete target, using its first allowed path prefix. */
export function defaultStartUrls(scope: Scope): string[] {
  const urls: string[] = [];
  for (const target of scope.targets) {
    if (!isConcreteHost(target.host)) continue;
    const path = target.paths && target.paths.length > 0 ? target.paths[0] : "/";
    urls.push(`${targetOrigin(target)}${path}`);
  }
  return [...new Set(urls)];
}

function dedupeTechnologies(markers: TechnologyMarker[]): TechnologyMarker[] {
  const seen = new Map<string, TechnologyMarker>();
  for (const marker of markers) {
    if (!seen.has(marker.name)) seen.set(marker.name, marker);
  }
  return [...seen.values()];
}

function formKey(form: CrawledForm): string {
  return `${form.method} ${form.action} ${form.pageUrl} ${form.parameters.join(",")}`;
}

/**
 * Read-only reconnaissance: crawl every concrete in-scope target through the
 * guarded client and aggregate an attack-surface summary. It performs no
 * state-changing requests and never needs the LLM.
 */
export async function runRecon(options: ReconOptions): Promise<ReconResult> {
  const maxDepth = options.maxDepth ?? 2;
  const maxUrls = options.maxUrls ?? 50;

  const client = new GuardedHttpClient({
    scope: options.scope,
    rateLimiter: options.rateLimiter,
    audit: options.audit,
    fetchFn: options.fetchFn,
    env: options.env,
    maxResponseBodyBytes: options.maxResponseBodyBytes,
  });
  const crawler = new Crawler({ client, scope: options.scope });

  const startUrls = options.startUrls ?? defaultStartUrls(options.scope);
  if (startUrls.length === 0) {
    return {
      ok: false,
      error: "no concrete in-scope start URL could be derived from the scope",
      scopeName: options.scope.name,
      crawls: [],
    };
  }

  const crawls: CrawlResult[] = [];
  for (const startUrl of startUrls) {
    const crawl = await crawler.crawl({
      startUrl,
      maxDepth,
      maxUrls,
      stayInScope: options.stayInScope,
    });
    crawls.push(crawl);
    if (!crawl.ok) {
      return {
        ok: false,
        error: crawl.error ?? `recon crawl failed for ${startUrl}`,
        scopeName: options.scope.name,
        crawls,
      };
    }
  }

  const urls: string[] = [];
  const seenUrls = new Set<string>();
  const forms: CrawledForm[] = [];
  const seenForms = new Set<string>();
  const assets = new Map<string, CrawledAsset>();
  const technologies: TechnologyMarker[] = [];
  const blocked: CrawledBlock[] = [];
  const seenBlocked = new Set<string>();
  let requests = 0;
  let truncated = false;

  for (const crawl of crawls) {
    for (const url of crawl.urls) {
      if (seenUrls.has(url)) continue;
      seenUrls.add(url);
      urls.push(url);
    }
    for (const form of crawl.forms) {
      const key = formKey(form);
      if (seenForms.has(key)) continue;
      seenForms.add(key);
      forms.push(form);
    }
    for (const asset of crawl.assets) {
      if (!assets.has(asset.url)) assets.set(asset.url, asset);
    }
    technologies.push(...crawl.technologies);
    for (const block of crawl.blocked) {
      if (seenBlocked.has(block.url)) continue;
      seenBlocked.add(block.url);
      blocked.push(block);
    }
    requests += crawl.requests;
    truncated = truncated || crawl.truncated;
  }

  return {
    ok: true,
    scopeName: options.scope.name,
    crawls,
    summary: {
      targets: options.scope.targets.map((target) => targetOrigin(target)),
      startUrls,
      urls,
      forms,
      assets: [...assets.values()],
      technologies: dedupeTechnologies(technologies),
      blocked,
      requests,
      truncated,
      maxDepth: crawls[0]?.maxDepth ?? maxDepth,
      maxUrls: crawls[0]?.maxUrls ?? maxUrls,
    },
  };
}
