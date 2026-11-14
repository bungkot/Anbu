/**
 * Generate a CycloneDX SBOM for the installed dependency tree and write it to
 * dist/sbom.json. Delegates to `npm sbom` so the document matches npm's own
 * resolution of package-lock.json.
 */
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const outputPath = join(root, "dist", "sbom.json");

const npmCli = process.env.npm_execpath;
const result = npmCli
  ? spawnSync(process.execPath, [npmCli, "sbom", "--sbom-format", "cyclonedx"], {
      cwd: root,
      encoding: "utf8",
    })
  : spawnSync("npm", ["sbom", "--sbom-format", "cyclonedx"], {
      cwd: root,
      encoding: "utf8",
      shell: true,
    });

if (result.error !== undefined) {
  console.error(result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(result.stderr ?? "npm sbom failed");
  process.exit(result.status);
}

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, result.stdout, "utf8");
console.log(`SBOM written to ${outputPath}`);
