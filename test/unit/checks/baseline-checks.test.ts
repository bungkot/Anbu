import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeDependencies,
  compareVersions,
  parseDependencies,
  parseLockfile,
} from "../../../src/tools/checks/dependencies.js";
import { analyzePasswordHash } from "../../../src/tools/checks/password-hash.js";
import { analyzeSecurityHeaders } from "../../../src/tools/checks/security-headers.js";
import { analyzeTls } from "../../../src/tools/checks/tls.js";
import { response } from "./helpers.js";

test("security-headers analyzer reports missing headers on HTTPS", () => {
  const findings = analyzeSecurityHeaders({
    url: "https://example.test/",
    headers: {},
  });
  assert.ok(findings.length >= 5);
  assert.ok(findings.some((finding) => /Strict-Transport-Security/.test(finding.title)));
  assert.ok(findings.some((finding) => /Content-Security-Policy/.test(finding.title)));
});

test("security-headers analyzer ignores a fully hardened response", () => {
  const findings = analyzeSecurityHeaders({
    url: "https://example.test/",
    headers: {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "geolocation=()",
      "x-content-type-options": "nosniff",
      "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
    },
  });
  assert.equal(findings.length, 0);
});

test("security-headers analyzer reports weak cookie flags", () => {
  const findings = analyzeSecurityHeaders({
    url: "https://example.test/",
    headers: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "geolocation=()",
      "x-content-type-options": "nosniff",
      "set-cookie": "session=abc",
    },
  });
  assert.equal(findings.length, 3);
});

test("TLS analyzer reports deprecated protocols and expired certificates", () => {
  const hsts = { "strict-transport-security": "max-age=31536000; includeSubDomains" };
  const deprecated = analyzeTls({
    url: "https://example.test/",
    headers: { ...hsts },
    protocol: "TLSv1.0",
  });
  assert.equal(deprecated.length, 1);
  assert.match(deprecated[0].title, /Deprecated TLS/);

  const expired = analyzeTls({
    url: "https://example.test/",
    headers: { ...hsts },
    protocol: "TLSv1.3",
    certificate: { validUntil: "2020-01-01T00:00:00Z" },
  });
  assert.equal(expired.length, 1);
  assert.match(expired[0].title, /expired/);

  const safe = analyzeTls({
    url: "https://example.test/",
    headers: { ...hsts },
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    certificate: { validUntil: "2030-01-01T00:00:00Z", keyBits: 256, keyAlgorithm: "EC" },
  });
  assert.equal(safe.length, 0);
});

test("password-hash analyzer detects weak and cleartext password fields", () => {
  const weakHash = analyzePasswordHash(
    response({ bodyText: '{"password":"5f4dcc3b5aa765d61d8327deb882cf99"}' }),
  );
  assert.ok(weakHash.length >= 1);
  assert.ok(weakHash.some((finding) => /Weak password hash/.test(finding.title)));

  const md5crypt = analyzePasswordHash(
    response({ bodyText: '{"hash":"$1$abcdef$abcdefghijklmnopqrstuv"}' }),
  );
  assert.ok(md5crypt.length >= 1);
  assert.ok(md5crypt.some((finding) => /md5crypt/.test(finding.title)));

  const safe = analyzePasswordHash(
    response({
      bodyText: '{"password":"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hashhashhash"}',
    }),
  );
  assert.equal(safe.length, 0);
});

test("dependencies analyzer matches vulnerable versions and ignores patched ones", () => {
  const vulnerable = analyzeDependencies([
    { name: "lodash", version: "4.17.20" },
    { name: "axios", version: "1.5.0" },
  ]);
  assert.equal(vulnerable.length, 2);

  const safe = analyzeDependencies([
    { name: "lodash", version: "4.17.21" },
    { name: "axios", version: "1.6.0" },
  ]);
  assert.equal(safe.length, 0);
});

test("dependency parsing and version comparison are deterministic", () => {
  assert.equal(compareVersions("4.17.20", "4.17.21"), -1);
  assert.equal(compareVersions("1.6.0", "1.6.0"), 0);
  assert.equal(compareVersions("1.10.0", "1.9.9"), 1);

  const parsed = parseDependencies([{ name: "lodash", version: "4.17.20" }]);
  assert.deepEqual(parsed, [{ name: "lodash", version: "4.17.20" }]);

  const lockfile = parseLockfile({
    packages: {
      "": { name: "app", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/axios": { version: "1.6.0" },
    },
  });
  assert.equal(lockfile.length, 2);
});
