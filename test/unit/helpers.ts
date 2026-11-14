import type { Scope } from "../../src/model/scope.js";

/** A valid scope document for tests, with per-test overrides. */
export function makeScope(overrides: Partial<Scope> = {}): Scope {
  return {
    version: 1,
    name: "test scope",
    authorization: {
      reference: "TEST-001",
      owner: "Test Owner",
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2030-01-01T00:00:00Z",
      token: "env:ANBU_AUTH_TOKEN",
    },
    targets: [
      {
        host: "example.test",
        scheme: "https",
        port: 443,
        paths: ["/"],
        methods: ["GET", "HEAD", "OPTIONS", "POST"],
      },
    ],
    deny: [],
    testClasses: ["A01", "A05"],
    readOnly: false,
    ...overrides,
  };
}
