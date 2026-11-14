import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeCheckInput } from "../../../src/tools/checks/sanitize.js";

test("sanitizeCheckInput retains the closed input needed to replay a check", () => {
  const result = sanitizeCheckInput({
    url: "https://example.test/api/users/1",
    method: "post",
    parameter: "id",
    options: { alternates: ["2", "3"] },
  });

  assert.equal(result.redacted, false);
  assert.equal(result.input.redacted, undefined);
  assert.equal(result.input.method, "POST");
  assert.equal(result.input.parameter, "id");
  assert.deepEqual(result.input.options, { alternates: ["2", "3"] });
});

test("sanitizeCheckInput omits defaults and empty values", () => {
  const result = sanitizeCheckInput({
    url: "https://example.test/",
    method: "GET",
    parameter: "   ",
    options: {},
  });

  assert.equal(result.redacted, false);
  assert.equal("method" in result.input, false);
  assert.equal("parameter" in result.input, false);
  assert.deepEqual(result.input.options, {});
});

test("sanitizeCheckInput redacts credentials in options and flags the input", () => {
  const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln";
  const result = sanitizeCheckInput({
    url: "https://example.test/login",
    options: {
      credentials: [{ username: "admin", password: "hunter2" }],
      token,
      usernameField: "user",
    },
  });

  assert.equal(result.redacted, true);
  assert.equal(result.input.redacted, true);
  const options = result.input.options as {
    credentials: Array<{ username: string; password: string }>;
    token: string;
    usernameField: string;
  };
  assert.equal(options.credentials[0].username, "admin");
  assert.equal(options.credentials[0].password, "[REDACTED]");
  assert.equal(options.token, "[REDACTED]");
  assert.equal(options.usernameField, "user");
});

test("sanitizeCheckInput redacts nested credentials in a JSON body", () => {
  const result = sanitizeCheckInput({
    url: "https://example.test/login",
    body: `{ "username": "admin", "password": "hunter2" }`,
  });

  assert.equal(result.redacted, true);
  assert.deepEqual(JSON.parse(result.input.body ?? ""), {
    username: "admin",
    password: "[REDACTED]",
  });
});

test("sanitizeCheckInput does not flag JSON reformatting as redaction", () => {
  const result = sanitizeCheckInput({
    url: "https://example.test/api",
    body: `{ "q": "1" }`,
  });

  assert.equal(result.redacted, false);
  assert.deepEqual(JSON.parse(result.input.body ?? ""), { q: "1" });
});

test("sanitizeCheckInput redacts credentials in a non-JSON body", () => {
  const result = sanitizeCheckInput({
    url: "https://example.test/login",
    body: "username=admin&password=hunter2",
  });

  assert.equal(result.redacted, true);
  assert.equal(result.input.body, "username=admin&password=[REDACTED]");
});
