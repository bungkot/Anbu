import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeCommandInjection } from "../../../src/tools/checks/command-injection.js";
import { analyzePathTraversal } from "../../../src/tools/checks/path-traversal.js";
import { analyzeSqlInjection } from "../../../src/tools/checks/sqli.js";
import { analyzeXss } from "../../../src/tools/checks/xss.js";
import { analyzeXxe } from "../../../src/tools/checks/xxe.js";
import { response } from "./helpers.js";

const url = "https://example.test/search";

test("SQLi analyzer detects a database error and ignores a safe response", () => {
  const baseline = response({ bodyText: "Welcome to the shop" });
  const vulnerable = analyzeSqlInjection({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload: "'",
        response: response({
          bodyText: "You have an error in your SQL syntax; check the manual",
        }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);
  assert.equal(vulnerable[0].severity, "high");

  const safe = analyzeSqlInjection({
    url,
    parameter: "q",
    baseline,
    probes: [{ payload: "'", response: response({ bodyText: "No results found" }) }],
  });
  assert.equal(safe.length, 0);
});

test("SQLi analyzer ignores a signature that is already in the baseline", () => {
  const baseline = response({ bodyText: "Warning: mysql_connect(): something went wrong" });
  const findings = analyzeSqlInjection({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload: "'",
        response: response({ bodyText: "Warning: mysql_connect(): something went wrong" }),
      },
    ],
  });
  assert.equal(findings.length, 0);
});

test("SQLi analyzer detects a boolean differential", () => {
  const baseline = response({ bodyText: "Welcome" });
  const findings = analyzeSqlInjection({
    url,
    parameter: "q",
    baseline,
    probes: [
      { payload: "1 AND 1=1", response: response({ bodyText: "Item one is in stock" }) },
      { payload: "1 AND 1=2", response: response({ bodyText: "Item one is out of stock" }) },
    ],
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /Boolean-based/);
});

test("XSS analyzer detects unescaped reflection and ignores encoded output", () => {
  const baseline = response({ bodyText: "Welcome" });
  const payload = "<script>anbumarker</script>";
  const vulnerable = analyzeXss({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload,
        response: response({ bodyText: `<div><script>anbumarker</script></div>` }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);

  const safe = analyzeXss({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload,
        response: response({
          bodyText: `<div>&lt;script&gt;anbumarker&lt;/script&gt;</div>`,
        }),
      },
    ],
  });
  assert.equal(safe.length, 0);
});

test("command-injection analyzer requires a shell error signature", () => {
  const baseline = response({ bodyText: "Welcome" });
  const vulnerable = analyzeCommandInjection({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload: ";anbumarker",
        response: response({ bodyText: "sh: 1: anbumarker: not found" }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);

  const reflectedOnly = analyzeCommandInjection({
    url,
    parameter: "q",
    baseline,
    probes: [
      {
        payload: ";anbumarker",
        response: response({ bodyText: "Search results for ;anbumarker" }),
      },
    ],
  });
  assert.equal(reflectedOnly.length, 0);
});

test("XXE analyzer detects an external entity error and ignores a safe response", () => {
  const baseline = response({ bodyText: "<ok/>" });
  const vulnerable = analyzeXxe({
    url,
    baseline,
    probes: [
      {
        payload: "<xml/>",
        response: response({
          bodyText: 'anbuxxe: failed to load external entity "file:///nonexistent-anbu-xxe"',
        }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);

  const safe = analyzeXxe({
    url,
    baseline,
    probes: [{ payload: "<xml/>", response: response({ bodyText: "<ok/>" }) }],
  });
  assert.equal(safe.length, 0);
});

test("path-traversal analyzer detects protected file content", () => {
  const baseline = response({ bodyText: "Welcome" });
  const vulnerable = analyzePathTraversal({
    url,
    parameter: "file",
    baseline,
    probes: [
      {
        payload: "../../../../etc/passwd",
        response: response({
          bodyText:
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        }),
      },
    ],
  });
  assert.equal(vulnerable.length, 1);

  const safe = analyzePathTraversal({
    url,
    parameter: "file",
    baseline,
    probes: [
      { payload: "../../../../etc/passwd", response: response({ bodyText: "File not found" }) },
    ],
  });
  assert.equal(safe.length, 0);
});

test("path-traversal analyzer ignores signatures already present in the baseline", () => {
  const baseline = response({ bodyText: "root:x:0:0:root:/root:/bin/bash" });
  const findings = analyzePathTraversal({
    url,
    parameter: "file",
    baseline,
    probes: [
      {
        payload: "../../../../etc/passwd",
        response: response({ bodyText: "root:x:0:0:root:/root:/bin/bash" }),
      },
    ],
  });
  assert.equal(findings.length, 0);
});
