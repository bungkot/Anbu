import { createServer, type Server, type ServerResponse } from "node:http";

export interface TargetFixtureRequest {
  method: string;
  url: string;
}

export interface TargetFixture {
  baseUrl: string;
  port: number;
  requests: TargetFixtureRequest[];
  close: () => Promise<void>;
}

const SERVER_HEADER = "AnbuTargetFixture/1.0";

function send(
  res: ServerResponse,
  status: number,
  contentType: string,
  body: string,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(status, {
    server: SERVER_HEADER,
    "content-type": contentType,
    ...extraHeaders,
  });
  res.end(body);
}

function html(res: ServerResponse, status: number, body: string): void {
  send(res, status, "text/html; charset=utf-8", body);
}

const ROOT_PAGE = [
  "<!doctype html>",
  "<html><head><title>Anbu target fixture</title></head><body>",
  "<h1>Deliberately vulnerable local fixture</h1>",
  '<a href="/search?q=test">Search</a>',
  '<a href="/api/data">API data</a>',
  '<form action="/login" method="get">',
  '<input name="username"><input name="password" type="password">',
  "</form>",
  "</body></html>",
].join("\n");

const LOGIN_PAGE = [
  "<!doctype html>",
  "<html><head><title>Login</title></head><body>",
  '<form action="/login" method="post">',
  '<input name="username"><input name="password" type="password">',
  "</form>",
  "</body></html>",
].join("\n");

function sqlErrorPage(): string {
  return [
    "<!doctype html>",
    "<html><body>You have an error in your SQL syntax; check the manual ",
    "that corresponds to your MySQL server version</body></html>",
  ].join("");
}

function searchPage(query: string): string {
  // The fixture intentionally reflects the query without encoding so the XSS
  // probe has a deterministic finding. Quote-containing input is answered with
  // a database error so the SQLi probe has a deterministic finding too.
  return `<!doctype html><html><body><div>results for ${query}</div></body></html>`;
}

/**
 * Deliberately vulnerable fixture bound to 127.0.0.1 on an ephemeral port.
 *
 * It mirrors the shape of an authorized assessment target: missing security
 * headers, reflected XSS in `/search`, SQL error disclosure, permissive CORS on
 * `/api/data`, an unauthenticated admin page, and an anonymously readable audit
 * log. Every response is deterministic so a baseline run reproduces exactly.
 */
export async function startTargetFixture(): Promise<TargetFixture> {
  const requests: TargetFixtureRequest[] = [];

  const server: Server = createServer((req, res) => {
    const rawUrl = req.url ?? "/";
    requests.push({ method: req.method ?? "GET", url: rawUrl });
    const url = new URL(rawUrl, "http://127.0.0.1");

    if (url.pathname === "/") {
      html(res, 200, ROOT_PAGE);
      return;
    }

    if (url.pathname === "/login") {
      html(res, 200, LOGIN_PAGE);
      return;
    }

    if (url.pathname === "/search") {
      const query = url.searchParams.get("q") ?? "";
      if (query.includes("'") || query.includes('"')) {
        html(res, 500, sqlErrorPage());
        return;
      }
      html(res, 200, searchPage(query));
      return;
    }

    if (url.pathname === "/api/data") {
      const origin = typeof req.headers.origin === "string" ? req.headers.origin : "";
      const corsHeaders: Record<string, string> = {
        "access-control-allow-origin": origin,
      };
      if (origin.length > 0) corsHeaders["access-control-allow-credentials"] = "true";
      send(
        res,
        200,
        "application/json; charset=utf-8",
        JSON.stringify({ ok: true, source: "target-fixture" }),
        corsHeaders,
      );
      return;
    }

    if (url.pathname === "/admin") {
      html(res, 200, "<html><body><h1>Admin dashboard</h1><p>user management</p></body></html>");
      return;
    }

    if (url.pathname === "/audit") {
      send(
        res,
        200,
        "application/json; charset=utf-8",
        JSON.stringify({ event: "login success", user: "admin" }),
      );
      return;
    }

    send(res, 404, "text/plain; charset=utf-8", "not found");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (typeof address !== "object" || address === null) {
    await closeServer(server);
    throw new Error("target fixture failed to bind to a local port");
  }

  const port = address.port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    requests,
    close: () => closeServer(server),
  };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}
