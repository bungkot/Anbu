import { createServer, type Server } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../../src/audit/log.js";
import { RateLimiter } from "../../src/guardrails/rate-limit.js";
import type { Scope } from "../../src/model/scope.js";
import { GuardedHttpClient } from "../../src/tools/http.js";

export interface FixtureRequest {
  method: string;
  url: string;
}

export interface IntegrationFixture {
  baseUrl: string;
  port: number;
  requests: FixtureRequest[];
  close: () => Promise<void>;
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

/**
 * Deliberately under-hardened local fixture bound to 127.0.0.1 on an ephemeral
 * port. It emits no security headers, reflects a search query, leaks a fake
 * credential once, redirects externally, and returns a one-shot database error
 * so the verify state has a non-reproducible candidate to discard.
 */
export async function startFixture(): Promise<IntegrationFixture> {
  const requests: FixtureRequest[] = [];
  let quoteProbeHits = 0;

  const server = createServer((req, res) => {
    const rawUrl = req.url ?? "/";
    requests.push({ method: req.method ?? "GET", url: rawUrl });
    const url = new URL(rawUrl, "http://127.0.0.1");

    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        [
          "<!doctype html><html><body>",
          '<a href="/search?q=test">Search</a>',
          '<a href="/login">Login</a>',
          '<form action="/search" method="get"><input name="q" value="test"></form>',
          "</body></html>",
        ].join("\n"),
      );
      return;
    }

    if (url.pathname === "/login") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        '<!doctype html><html><body><form action="/login" method="post">' +
          '<input name="username"><input name="password" type="password"></form></body></html>',
      );
      return;
    }

    if (url.pathname === "/search") {
      const query = url.searchParams.get("q") ?? "";
      if (query.includes("'")) {
        quoteProbeHits += 1;
        if (quoteProbeHits === 1) {
          res.writeHead(500, { "content-type": "text/html; charset=utf-8" });
          res.end(
            "<html><body>You have an error in your SQL syntax; check the manual " +
              "that corresponds to your MySQL server version</body></html>",
          );
          return;
        }
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<html><body>results for ${query}</body></html>`);
      return;
    }

    if (url.pathname === "/leak") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("access_token=smoke-secret-value&note=safe");
      return;
    }

    if (url.pathname === "/redirect") {
      res.writeHead(302, { location: "http://external.invalid/leaked" });
      res.end();
      return;
    }

    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (typeof address !== "object" || address === null) {
    await closeServer(server);
    throw new Error("integration fixture failed to bind to a local port");
  }

  const port = address.port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    requests,
    close: () => closeServer(server),
  };
}

/** A valid read-only scope aimed at the local fixture. */
export function localScope(port: number, overrides: Partial<Scope> = {}): Scope {
  return {
    version: 1,
    name: "integration scope",
    authorization: {
      reference: "INT-001",
      owner: "Anbu integration tests",
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2030-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN",
    },
    targets: [
      {
        host: "127.0.0.1",
        scheme: "http",
        port,
        paths: ["/"],
        methods: ["GET", "HEAD", "OPTIONS"],
      },
    ],
    deny: [],
    testClasses: ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
    readOnly: true,
    policy: {
      requestsPerSecondPerHost: 1000,
      maxRequests: 500,
      maxBodyBytes: 65_536,
      maxRedirects: 3,
      followExternalRedirects: false,
    },
    ...overrides,
  };
}

export interface HarnessOptions {
  requestsPerSecondPerHost?: number;
  maxRequests?: number;
  env?: (name: string) => string | undefined;
}

/** Build a real guarded client over temp audit storage and a fixed token. */
export async function makeHarness(
  scope: Scope,
  options: HarnessOptions = {},
): Promise<{ dir: string; audit: AuditLog; client: GuardedHttpClient }> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-int-"));
  const audit = new AuditLog(join(dir, "audit.log"), "integration-run");
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost: options.requestsPerSecondPerHost ?? 1000,
    maxRequests: options.maxRequests ?? 500,
  });
  const client = new GuardedHttpClient({
    scope,
    rateLimiter,
    audit,
    env: options.env ?? (() => "test-token"),
  });
  return { dir, audit, client };
}

/** Write a scope document to a temp file for commands that load from disk. */
export async function writeScopeFile(value: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "anbu-int-scope-"));
  const path = join(dir, "scope.json");
  await writeFile(path, JSON.stringify(value), "utf8");
  return path;
}
