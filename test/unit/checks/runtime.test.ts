import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeErrorHandling,
  analyzeServerVersionHeaders,
} from "../../../src/tools/checks/error-handling.js";
import { analyzeLogging } from "../../../src/tools/checks/logging.js";
import { analyzeDeserialization } from "../../../src/tools/checks/deserialization.js";
import { analyzeRateLimit } from "../../../src/tools/checks/rate-limit.js";
import { analyzeUpload } from "../../../src/tools/checks/upload.js";
import { response } from "./helpers.js";

const url = "https://example.test/api";

test("error-handling analyzer detects stack traces and ignores generic errors", () => {
  const baseline = response({ bodyText: "Welcome" });
  const vulnerable = analyzeErrorHandling({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload: "<bad",
        response: response({
          status: 500,
          bodyText: "Stack Trace\n at com.example.Foo.bar(Foo.java:42)",
        }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);
  assert.equal(vulnerable[0].severity, "medium");

  const safe = analyzeErrorHandling({
    url,
    parameter: "q",
    baseline,
    probes: [{ payload: "<bad", response: response({ status: 400, bodyText: "Invalid input" }) }],
  });
  assert.equal(safe.length, 0);
});

test("server version headers are reported at low severity", () => {
  const findings = analyzeServerVersionHeaders(
    response({ headers: { server: "Apache/2.4.41", "x-powered-by": "PHP/8.1.2" } }),
  );
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => finding.severity === "low"));
});

test("logging analyzer detects an anonymously exposed audit log", () => {
  const findings = analyzeLogging({
    url,
    primary: response({ headers: {} }),
    probes: [
      {
        path: "/audit",
        response: response({
          status: 200,
          bodyText: '{"event":"login","user":"admin","ip":"10.0.0.1"}',
        }),
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("logging analyzer reports missing correlation evidence only as low confidence", () => {
  const findings = analyzeLogging({
    url,
    primary: response({ headers: {} }),
    probes: [{ path: "/audit", response: response({ status: 404, bodyText: "Not found" }) }],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "low");
  assert.equal(findings[0].confidence, "unverified");
});

test("logging analyzer ignores a correlated response with no exposed logs", () => {
  const findings = analyzeLogging({
    url,
    primary: response({ headers: { "x-request-id": "req-123" } }),
    probes: [{ path: "/audit", response: response({ status: 404, bodyText: "Not found" }) }],
  });
  assert.equal(findings.length, 0);
});

test("deserialization analyzer detects unsafe serialization markers", () => {
  const dotNet = analyzeDeserialization({
    url,
    body: "rO0ABXNyABFqYXZhLnV0aWwuSXRlcmF0b3I=",
  });
  assert.equal(dotNet.length, 1);

  const php = analyzeDeserialization({ url, body: 'O:8:"stdClass":1:{"id":1}' });
  assert.equal(php.length, 1);

  const safe = analyzeDeserialization({ url, body: '{"user":"anbu"}' });
  assert.equal(safe.length, 0);
});

test("upload analyzer detects a stored and served harmless HTML file", () => {
  const findings = analyzeUpload({
    url,
    upload: response({ status: 200, bodyText: '{"url":"/uploads/anbu-check.html"}' }),
    retrieval: response({ status: 200, bodyText: "<p>anbumarker</p>" }),
    marker: "anbumarker",
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("upload analyzer ignores rejected or unretrieved uploads", () => {
  const rejected = analyzeUpload({
    url,
    upload: response({ status: 415, bodyText: '{"error":"unsupported media type"}' }),
    marker: "anbumarker",
  });
  assert.equal(rejected.length, 0);

  const notRetrieved = analyzeUpload({
    url,
    upload: response({ status: 200, bodyText: '{"url":"/uploads/anbu-check.html"}' }),
    retrieval: response({ status: 403, bodyText: "Forbidden" }),
    marker: "anbumarker",
  });
  assert.equal(notRetrieved.length, 0);
});

test("rate-limit analyzer detects an unthrottled burst", () => {
  const responses = Array.from({ length: 12 }, () => response({ status: 200 }));
  const findings = analyzeRateLimit({ url, responses });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "medium");
});

test("rate-limit analyzer ignores throttled or quota-advertised bursts", () => {
  const throttled = Array.from({ length: 12 }, (_unused, index) =>
    response({ status: index === 11 ? 429 : 200 }),
  );
  assert.equal(analyzeRateLimit({ url, responses: throttled }).length, 0);

  const quota = Array.from({ length: 12 }, () =>
    response({ status: 200, headers: { "x-ratelimit-remaining": "9" } }),
  );
  assert.equal(analyzeRateLimit({ url, responses: quota }).length, 0);

  const tooFew = Array.from({ length: 4 }, () => response({ status: 200 }));
  assert.equal(analyzeRateLimit({ url, responses: tooFew }).length, 0);
});
