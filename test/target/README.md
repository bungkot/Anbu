# Target baselines

Target baselines prove the engine against a known-vulnerable application. A
baseline records the deterministic check ids that must be reported for one
fixture, so a regression surfaces as a missing or unexpected check instead of a
silent diff in a report file.

## Baselines

| Fixture | File | Status |
|---|---|---|
| `test/target/fixture.ts` (127.0.0.1, ephemeral port) | `baselines/local-fixture.json` | `recorded` |
| `https://demo.testfire.net/` (Altoro Mutual) | `baselines/altoro-mutual.json` | `pending-authorization` |

Run the suite with:

```bash
npm run test:target
```

The local fixture binds to `127.0.0.1` on an ephemeral port and is fully
deterministic. It is exercised with the model disabled and a wrapped `fetch`
that fails loudly if any request leaves the fixture origin.

## Recording a baseline

1. Run the engine against the fixture with the model disabled.
2. Collect the check ids from `compareBaseline` (`reportedCheckIds`).
3. Write them to `expectedReportedCheckIds` in the baseline JSON and set
   `status` to `recorded`.
4. Store the producing run under `workspace/evidence/target-runs/` and note the
   run id in the baseline's `notes`.

`compareBaseline` treats `confirmed` and `probable` findings as reported and
excludes `discarded` candidates. Entries in `ignoredCheckIds` are excluded with
a reason. A `pending-authorization` baseline can never compare as passing.

## External targets

Altoro Mutual is an external host. It may only be exercised with a written
authorization from the asset owner, a valid scope document, and a resolved
`ANBU_AUTH_TOKEN`. This repository holds no such authorization, so its baseline
stays `pending-authorization` and no request is sent to the host. Never run an
external target outside those guardrails; see
[`docs/scope-and-authorization.md`](../../../docs/scope-and-authorization.md)
and [`docs/verification.md`](../../../docs/verification.md).
