import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeAuthzMethods } from "../../../src/tools/checks/authz-methods.js";
import { analyzeCors } from "../../../src/tools/checks/cors.js";
import { analyzeForceBrowsing } from "../../../src/tools/checks/force-browsing.js";
import { analyzeIdor } from "../../../src/tools/checks/idor.js";
import { response } from "./helpers.js";

const url = "https://example.test/api/account";

test("IDOR analyzer detects a forbidden-to-readable transition", () => {
  const findings = analyzeIdor({
    url,
    parameter: "id",
    baseline: response({ status: 403, bodyText: '{"error":"forbidden"}' }),
    probes: [
      {
        value: "2",
        response: response({ status: 200, bodyText: '{"id":2,"email":"victim@example.test"}' }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("IDOR analyzer detects a different object returned for the same session", () => {
  const findings = analyzeIdor({
    url,
    parameter: "id",
    baseline: response({ status: 200, bodyText: '{"id":1,"email":"user@example.test"}' }),
    probes: [
      {
        value: "2",
        response: response({ status: 200, bodyText: '{"id":2,"email":"victim@example.test"}' }),
      },
    ],
  });
  assert.equal(findings.length, 1);
});

test("IDOR analyzer ignores identical or still-forbidden responses", () => {
  const same = analyzeIdor({
    url,
    parameter: "id",
    baseline: response({ status: 200, bodyText: '{"id":1,"email":"user@example.test"}' }),
    probes: [
      {
        value: "2",
        response: response({ status: 200, bodyText: '{"id":1,"email":"user@example.test"}' }),
      },
    ],
  });
  assert.equal(same.length, 0);

  const stillForbidden = analyzeIdor({
    url,
    parameter: "id",
    baseline: response({ status: 403, bodyText: '{"error":"forbidden"}' }),
    probes: [
      { value: "2", response: response({ status: 403, bodyText: '{"error":"forbidden"}' }) },
    ],
  });
  assert.equal(stillForbidden.length, 0);
});

test("force-browsing analyzer detects administrative content", () => {
  const findings = analyzeForceBrowsing({
    url,
    probes: [
      {
        path: "/admin",
        response: response({
          status: 200,
          bodyText: "<h1>Admin Dashboard</h1><p>User Management</p>",
        }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("force-browsing analyzer ignores forbidden and login pages", () => {
  const forbidden = analyzeForceBrowsing({
    url,
    probes: [{ path: "/admin", response: response({ status: 403, bodyText: "Forbidden" }) }],
  });
  assert.equal(forbidden.length, 0);

  const login = analyzeForceBrowsing({
    url,
    probes: [
      {
        path: "/admin",
        response: response({
          status: 200,
          bodyText: '<title>Login</title><input name="password" type="password">',
        }),
      },
    ],
  });
  assert.equal(login.length, 0);
});

test("force-browsing analyzer detects readable sensitive files", () => {
  const findings = analyzeForceBrowsing({
    url,
    probes: [
      {
        path: "/.env",
        response: response({
          status: 200,
          bodyText: "APP_DEBUG=false\nAPP_KEY=base64:abc\nDB_PASSWORD=secret",
        }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /Sensitive file/);
});

test("CORS analyzer detects credentialed origin reflection", () => {
  const findings = analyzeCors({
    url,
    probes: [
      {
        origin: "https://evil.test",
        response: response({
          headers: {
            "access-control-allow-origin": "https://evil.test",
            "access-control-allow-credentials": "true",
          },
        }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("CORS analyzer ignores absent or trusted policies", () => {
  const absent = analyzeCors({
    url,
    probes: [{ origin: "https://evil.test", response: response({ headers: {} }) }],
  });
  assert.equal(absent.length, 0);

  const trusted = analyzeCors({
    url,
    probes: [
      {
        origin: "https://evil.test",
        response: response({
          headers: { "access-control-allow-origin": "https://trusted.test" },
        }),
      },
    ],
  });
  assert.equal(trusted.length, 0);
});

test("authz-methods analyzer detects anonymous state-changing acceptance", () => {
  const findings = analyzeAuthzMethods({
    url,
    probes: [{ method: "DELETE", response: response({ status: 200, bodyText: '{"ok":true}' }) }],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("authz-methods analyzer ignores 401/403/405 responses", () => {
  const findings = analyzeAuthzMethods({
    url,
    probes: [
      { method: "DELETE", response: response({ status: 403, bodyText: "Forbidden" }) },
      { method: "PUT", response: response({ status: 401, bodyText: "Unauthorized" }) },
      { method: "POST", response: response({ status: 405, bodyText: "Method Not Allowed" }) },
    ],
  });
  assert.equal(findings.length, 0);
});
