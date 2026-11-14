import { evaluateScope } from "../guardrails/scope.js";
import type { Scope } from "../model/scope.js";
import { parse } from "parse5";
import type { DefaultTreeAdapterTypes } from "parse5";
import type { GuardedHttpClient } from "./http.js";

type Element = DefaultTreeAdapterTypes.Element;
type Node = DefaultTreeAdapterTypes.Node;

const DEFAULT_MAX_DEPTH = 2;
const DEFAULT_MAX_URLS = 50;
const MAX_URL_LENGTH = 2048;

const TECHNOLOGY_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: "angular", pattern: /angular/i },
  { name: "bootstrap", pattern: /bootstrap/i },
  { name: "font-awesome", pattern: /font-?awesome/i },
  { name: "jquery", pattern: /jquery/i },
  { name: "next.js", pattern: /_next\// },
  { name: "react", pattern: /react(?:\.min)?\.js|react-dom/i },
  { name: "tailwind", pattern: /tailwind/i },
  { name: "vue", pattern: /vue\.(?:min\.)?js|vue\.runtime|vue\.global/i },
];

const HEADER_TECHNOLOGIES: ReadonlyArray<{ header: string; name: string }> = [
  { header: "server", name: "server" },
  { header: "x-powered-by", name: "x-powered-by" },
  { header: "x-generator", name: "x-generator" },
  { header: "x-aspnet-version", name: "asp.net" },
  { header: "x-aspnetmvc-version", name: "asp.net-mvc" },
];

export type FormMethod = "GET" | "POST";
export type AssetType = "script" | "stylesheet" | "image" | "media" | "document" | "other";

export interface CrawledForm {
  /** Absolute URL of the page that contains the form. */
  pageUrl: string;
  action: string;
  method: FormMethod;
  parameters: string[];
}

export interface CrawledAsset {
  url: string;
  type: AssetType;
}

export interface TechnologyMarker {
  name: string;
  evidence: string;
}

export interface CrawledBlock {
  url: string;
  reason: string;
}

export interface CrawlOptions {
  startUrl: string;
  /** Maximum link depth from the start URL. Default 2. */
  maxDepth?: number;
  /** Maximum number of URLs to fetch. Default 50. */
  maxUrls?: number;
  /** Only follow links that stay inside the scope allowlist. Default true. */
  stayInScope?: boolean;
}

export interface CrawlResult {
  startUrl: string;
  ok: boolean;
  error?: string;
  urls: string[];
  forms: CrawledForm[];
  assets: CrawledAsset[];
  technologies: TechnologyMarker[];
  requests: number;
  blocked: CrawledBlock[];
  /** True when the crawl stopped before visiting every discovered URL. */
  truncated: boolean;
  maxDepth: number;
  maxUrls: number;
}

interface RawForm {
  action: string;
  method: FormMethod;
  parameters: string[];
}

interface RawAsset {
  url: string;
  type: AssetType;
}

interface PageExtraction {
  links: string[];
  forms: RawForm[];
  assets: RawAsset[];
  technologies: TechnologyMarker[];
  /** Resolved `<base href>` for this page, if present. */
  baseUrl?: string;
}

interface QueueItem {
  url: string;
  depth: number;
}

function attrValue(element: Element, name: string): string | undefined {
  return element.attrs.find((attr) => attr.name === name)?.value;
}

function walkElements(node: Node, visit: (element: Element) => void): void {
  if ("tagName" in node) visit(node);
  if (node.nodeName === "template" && "content" in node) {
    for (const child of node.content.childNodes) walkElements(child, visit);
    return;
  }
  if ("childNodes" in node) {
    for (const child of node.childNodes) walkElements(child, visit);
  }
}

function detectTechnologyFromUrl(rawUrl: string, markers: TechnologyMarker[]): void {
  for (const { name, pattern } of TECHNOLOGY_PATTERNS) {
    if (pattern.test(rawUrl)) markers.push({ name, evidence: rawUrl });
  }
}

function extractPage(
  pageUrl: string,
  html: string,
  headers: Record<string, string>,
): PageExtraction {
  const document = parse(html);
  const links: string[] = [];
  const forms: RawForm[] = [];
  const assets: RawAsset[] = [];
  const technologies: TechnologyMarker[] = [];
  let baseUrl: string | undefined;

  walkElements(document, (element) => {
    switch (element.tagName.toLowerCase()) {
      case "base": {
        const href = attrValue(element, "href");
        if (href !== undefined) baseUrl = normalizeUrl(href, pageUrl);
        break;
      }
      case "a":
      case "area": {
        const href = attrValue(element, "href");
        if (href !== undefined) links.push(href);
        break;
      }
      case "link": {
        const href = attrValue(element, "href");
        if (href === undefined) break;
        const rel = (attrValue(element, "rel") ?? "").toLowerCase();
        const type = (attrValue(element, "type") ?? "").toLowerCase();
        const assetType: AssetType =
          rel.includes("stylesheet") || type.includes("css")
            ? "stylesheet"
            : rel.includes("icon")
              ? "image"
              : "other";
        assets.push({ url: href, type: assetType });
        detectTechnologyFromUrl(href, technologies);
        break;
      }
      case "script": {
        const src = attrValue(element, "src");
        if (src !== undefined) {
          assets.push({ url: src, type: "script" });
          detectTechnologyFromUrl(src, technologies);
        }
        break;
      }
      case "img": {
        const src = attrValue(element, "src");
        if (src !== undefined) assets.push({ url: src, type: "image" });
        break;
      }
      case "source":
      case "video":
      case "audio": {
        const src = attrValue(element, "src");
        if (src !== undefined) assets.push({ url: src, type: "media" });
        break;
      }
      case "iframe": {
        const src = attrValue(element, "src");
        if (src !== undefined) assets.push({ url: src, type: "document" });
        break;
      }
      case "form": {
        const action = attrValue(element, "action") ?? pageUrl;
        const rawMethod = (attrValue(element, "method") ?? "get").toLowerCase();
        const method: FormMethod = rawMethod === "post" ? "POST" : "GET";
        const parameters: string[] = [];
        walkElements(element, (child) => {
          const tag = child.tagName.toLowerCase();
          if (tag === "input" || tag === "select" || tag === "textarea" || tag === "button") {
            const name = attrValue(child, "name");
            if (name !== undefined && !parameters.includes(name)) parameters.push(name);
          }
        });
        forms.push({ action, method, parameters });
        break;
      }
      case "meta": {
        const name = (attrValue(element, "name") ?? "").toLowerCase();
        const content = attrValue(element, "content");
        if (name === "generator" && content !== undefined && content.length > 0) {
          technologies.push({ name: "generator", evidence: content });
        }
        break;
      }
      default:
        break;
    }
  });

  for (const [header, value] of Object.entries(headers)) {
    if (value.length === 0) continue;
    const match = HEADER_TECHNOLOGIES.find((entry) => entry.header === header.toLowerCase());
    if (match !== undefined) technologies.push({ name: match.name, evidence: value });
  }

  return { links, forms, assets, technologies, baseUrl };
}

function normalizeUrl(raw: string, base?: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_URL_LENGTH) return undefined;
  if (/^(?:javascript|mailto|tel|data|file|ftp):/i.test(trimmed)) return undefined;

  let url: URL;
  try {
    url = base === undefined ? new URL(trimmed) : new URL(trimmed, base);
  } catch {
    return undefined;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
  if (url.username !== "" || url.password !== "") return undefined;

  url.hash = "";
  if (
    (url.protocol === "http:" && url.port === "80") ||
    (url.protocol === "https:" && url.port === "443")
  ) {
    url.port = "";
  }
  return url.toString();
}

function isHtml(contentType: string, body: string): boolean {
  const normalized = contentType.toLowerCase();
  if (normalized.includes("text/html") || normalized.includes("application/xhtml+xml")) {
    return true;
  }
  if (normalized.length > 0) return false;
  return /^\s*(?:<!doctype\s+html|<html)/i.test(body);
}

function normalizeLimit(value: number | undefined, fallback: number, minimum: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.floor(value));
}

function dedupeTechnologies(markers: TechnologyMarker[]): TechnologyMarker[] {
  const seen = new Map<string, TechnologyMarker>();
  for (const marker of markers) {
    if (!seen.has(marker.name)) seen.set(marker.name, marker);
  }
  return [...seen.values()];
}

function emptyResult(
  startUrl: string,
  maxDepth: number,
  maxUrls: number,
  error: string,
): CrawlResult {
  return {
    startUrl,
    ok: false,
    error,
    urls: [],
    forms: [],
    assets: [],
    technologies: [],
    requests: 0,
    blocked: [],
    truncated: false,
    maxDepth,
    maxUrls,
  };
}

/**
 * Read-only crawl and attack-surface discovery. Every page request goes through
 * the guarded HTTP client, so scope, deny, authorization, policy, and rate
 * limits apply to discovery exactly as they apply to explicit probes.
 */
export class Crawler {
  private readonly client: GuardedHttpClient;
  private readonly scope: Scope;

  constructor(options: { client: GuardedHttpClient; scope: Scope }) {
    this.client = options.client;
    this.scope = options.scope;
  }

  async crawl(options: CrawlOptions): Promise<CrawlResult> {
    const maxDepth = normalizeLimit(options.maxDepth, DEFAULT_MAX_DEPTH, 0);
    const maxUrls = normalizeLimit(options.maxUrls, DEFAULT_MAX_URLS, 1);

    const startUrl = normalizeUrl(options.startUrl);
    if (startUrl === undefined) {
      return emptyResult(options.startUrl, maxDepth, maxUrls, "start URL is invalid");
    }
    const startDecision = evaluateScope(this.scope, { method: "GET", url: startUrl });
    if (!startDecision.allowed) {
      return emptyResult(
        startUrl,
        maxDepth,
        maxUrls,
        startDecision.reason ?? "start URL is out of scope",
      );
    }

    const queue: QueueItem[] = [{ url: startUrl, depth: 0 }];
    const queued = new Set<string>([startUrl]);
    const visited = new Set<string>();
    const urls: string[] = [];
    const forms: CrawledForm[] = [];
    const assets = new Map<string, CrawledAsset>();
    const technologies: TechnologyMarker[] = [];
    const blocked: CrawledBlock[] = [];
    let requests = 0;
    let truncated = false;

    while (queue.length > 0) {
      if (visited.size >= maxUrls) {
        truncated = true;
        break;
      }
      const item = queue.shift();
      if (item === undefined || visited.has(item.url)) continue;
      visited.add(item.url);
      urls.push(item.url);

      const outcome = await this.client.request({ method: "GET", url: item.url });
      requests += 1;

      if (!outcome.ok) {
        const reason = outcome.error ?? "request blocked";
        blocked.push({ url: item.url, reason });
        if (/budget exhausted/i.test(reason)) {
          truncated = true;
          break;
        }
        continue;
      }

      const response = outcome.response;
      if (response === undefined) continue;
      const contentType = response.headers["content-type"] ?? "";
      if (!isHtml(contentType, response.bodyText)) continue;

      const extraction = extractPage(item.url, response.bodyText, response.headers);
      technologies.push(...extraction.technologies);
      const resolveBase = extraction.baseUrl ?? item.url;

      for (const form of extraction.forms) {
        const action = normalizeUrl(form.action, resolveBase);
        if (action === undefined) continue;
        forms.push({
          pageUrl: item.url,
          action,
          method: form.method,
          parameters: form.parameters,
        });
      }

      for (const asset of extraction.assets) {
        const url = normalizeUrl(asset.url, resolveBase);
        if (url === undefined || assets.has(url)) continue;
        assets.set(url, { url, type: asset.type });
      }

      for (const rawLink of extraction.links) {
        const url = normalizeUrl(rawLink, resolveBase);
        if (url === undefined) continue;
        if (options.stayInScope !== false && !this.isUrlAllowed(url)) continue;
        if (visited.has(url) || queued.has(url)) continue;
        if (queued.size >= maxUrls) {
          truncated = true;
          continue;
        }
        if (item.depth >= maxDepth) continue;
        queue.push({ url, depth: item.depth + 1 });
        queued.add(url);
      }
    }

    return {
      startUrl,
      ok: true,
      urls,
      forms,
      assets: [...assets.values()],
      technologies: dedupeTechnologies(technologies),
      requests,
      blocked,
      truncated,
      maxDepth,
      maxUrls,
    };
  }

  private isUrlAllowed(url: string): boolean {
    return evaluateScope(this.scope, { method: "GET", url }).allowed;
  }
}
