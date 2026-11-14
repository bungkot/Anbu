import { test } from "node:test";
import assert from "node:assert/strict";
import { idorCheck } from "../../../src/tools/checks/idor.js";
import { jwtCheck } from "../../../src/tools/checks/jwt.js";
import { makeCheckContext } from "./helpers.js";

test("checks attach the sanitized closed input to their findings", async () => {
  const { ctx } = await makeCheckContext({
    fetchFn: async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("id=1")) {
        return new Response('{"error":"forbidden"}', {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response('{"id":2,"email":"victim@example.test"}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const result = await idorCheck.run(ctx, {
    url: "https://example.test/api/account?id=1",
    parameter: "id",
    options: { alternates: ["2"] },
  });

  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].checkInput, {
    parameter: "id",
    options: { alternates: ["2"] },
  });
});

test("checks flag redacted option values so verification does not replay them", async () => {
  const { ctx } = await makeCheckContext();
  const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln";

  const result = await jwtCheck.run(ctx, {
    url: "https://example.test/api",
    options: { token },
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].checkInput?.redacted, true);
  assert.equal((result.findings[0].checkInput?.options as { token?: string }).token, "[REDACTED]");
});
