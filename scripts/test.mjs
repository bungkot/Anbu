/**
 * Cross-version test runner. Discovers `.test.ts` files and runs them through
 * Node's built-in test runner with the tsx loader, so it works on Node >= 20.
 *
 * Usage:
 *   node scripts/test.mjs [directory]
 */
import { spawnSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const requested = process.argv[2];
const testDir = requested === undefined ? join(root, "test", "unit") : resolve(root, requested);

const discovered = await readdir(testDir, { recursive: true });
const files = discovered
  .filter((name) => name.endsWith(".test.ts"))
  .map((name) => (isAbsolute(name) ? name : join(testDir, name)))
  .sort();

if (files.length === 0) {
  console.error(`No .test.ts files found in ${testDir}`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--import", "tsx", "--test", ...files], {
  cwd: root,
  stdio: "inherit",
});

process.exit(result.status ?? 1);
