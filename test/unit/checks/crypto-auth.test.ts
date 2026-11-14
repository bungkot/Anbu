import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeDefaultCredentials,
} from "../../../src/tools/checks/default-credentials.js";
import {
  analyzeJwt,
  extractJwt,
} from "../../../src/tools/checks/jwt.js";
import { response } from "./helpers.js";

const url = "https://example.test/api/session";
const now = new Date("2026-01-01T00:00:00Z");

function makeToken(header: object, payload: object, signature = "c2ln"): string {
  return `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(
    JSON.stringify(payload),
  ).toString("base64url")}.${signature}`;
}

test("JWT analyzer detects the 'none' algorithm", () => {
  const token = makeToken({ alg: "none", typ: "JWT" }, { sub: "1" }, "");
  const findings = analyzeJwt({ url, token, now });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /none/);
});

test("JWT analyzer detects an expired token", () => {
  const token = makeToken({ alg: "RS256" }, { sub: "1", exp: 1000 });
  const findings = analyzeJwt({ url, token, now });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /expired/);
});

test("JWT analyzer detects a missing signature segment", () => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: "1" })).toString("base64url");
  const findings = analyzeJwt({ url, token: `${header}.${payload}`, now });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /signature/);
});

test("JWT analyzer detects a token exposed in the query string", () => {
  const token = makeToken({ alg: "RS256" }, { sub: "1", exp: 4102444800 });
  const findings = analyzeJwt({
    url: `${url}?access_token=${token}`,
    token,
    now,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /query/);
});

test("JWT analyzer accepts a valid RS256 token with a future expiry", () => {
  const token = makeToken({ alg: "RS256", typ: "JWT" }, { sub: "1", exp: 4102444800 });
  const findings = analyzeJwt({ url, token, now });
  assert.equal(findings.length, 0);
});

test("extractJwt finds a token in the body and in a cookie", () => {
  const token = makeToken({ alg: "RS256" }, { sub: "1" });
  const fromBody = extractJwt(response({ bodyText: `{"token":"${token}"}` }));
  assert.equal(fromBody, token);
  const fromCookie = extractJwt(
    response({ headers: { "set-cookie": `session=${token}; HttpOnly` } }),
  );
  assert.equal(fromCookie, token);
  assert.equal(extractJwt(response({ bodyText: "no token here" })), undefined);
});

test("default-credentials analyzer detects an accepted default login", () => {
  const findings = analyzeDefaultCredentials({
    url,
    probes: [
      {
        username: "admin",
        response: response({
          status: 200,
          headers: { "set-cookie": "session=abc; HttpOnly" },
          bodyText: "Welcome back",
        }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("default-credentials analyzer ignores rejected or inconclusive logins", () => {
  const rejected = analyzeDefaultCredentials({
    url,
    probes: [
      { username: "admin", response: response({ status: 401, bodyText: "Invalid credentials" }) },
    ],
  });
  assert.equal(rejected.length, 0);

  const inconclusive = analyzeDefaultCredentials({
    url,
    probes: [{ username: "admin", response: response({ status: 200, bodyText: "OK" }) }],
  });
  assert.equal(inconclusive.length, 0);
});
