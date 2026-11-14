import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Severity } from "../../model/finding.js";
import type {
  CandidateFinding,
  Check,
  CheckResult,
} from "./types.js";
import { checkResult } from "./types.js";
import { materialize, readOptionString } from "./util.js";

export interface DependencyRef {
  name: string;
  version: string;
}

export interface DependencyAdvisory {
  package: string;
  /** Versions strictly below this value are vulnerable. */
  below: string;
  cve: string;
  severity: Severity;
  summary: string;
  reference: string;
}

/**
 * Curated offline advisory snapshot. It is intentionally small and
 * deterministic so the check never needs the network; refresh it from OSV or
 * the GitHub Advisory Database before production use.
 */
export const DEPENDENCY_ADVISORIES: readonly DependencyAdvisory[] = [
  {
    package: "lodash",
    below: "4.17.21",
    cve: "CVE-2021-23337",
    severity: "high",
    summary: "Command injection via template.",
    reference: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
  },
  {
    package: "minimist",
    below: "1.2.6",
    cve: "CVE-2021-44906",
    severity: "high",
    summary: "Prototype pollution.",
    reference: "https://github.com/advisories/GHSA-xvch-5gv4-984h",
  },
  {
    package: "semver",
    below: "7.5.2",
    cve: "CVE-2022-25883",
    severity: "medium",
    summary: "Regular-expression denial of service.",
    reference: "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw",
  },
  {
    package: "word-wrap",
    below: "1.2.4",
    cve: "CVE-2023-26115",
    severity: "medium",
    summary: "Regular-expression denial of service.",
    reference: "https://github.com/advisories/GHSA-j8xg-qw4c-5g2g",
  },
  {
    package: "axios",
    below: "1.6.0",
    cve: "CVE-2023-45857",
    severity: "high",
    summary: "SSRF and exposure of confidential credentials.",
    reference: "https://github.com/advisories/GHSA-cph5-m8f7-6c5x",
  },
  {
    package: "tough-cookie",
    below: "4.1.3",
    cve: "CVE-2023-26136",
    severity: "medium",
    summary: "Prototype pollution.",
    reference: "https://github.com/advisories/GHSA-72xf-g2v4-qvf3",
  },
];

/** Parse a numeric dotted version, ignoring range prefixes and pre-release suffixes. */
export function versionParts(version: string): number[] | undefined {
  const cleaned = version.trim().replace(/^[v^~>=<\s]+/, "");
  const core = cleaned.split(/[-+]/, 1)[0];
  if (!/^\d+(?:\.\d+)*$/.test(core)) return undefined;
  return core.split(".").map((part) => Number(part));
}

export function compareVersions(left: string, right: string): number {
  const a = versionParts(left);
  const b = versionParts(right);
  if (a === undefined || b === undefined) return 0;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const leftPart = a[i] ?? 0;
    const rightPart = b[i] ?? 0;
    if (leftPart < rightPart) return -1;
    if (leftPart > rightPart) return 1;
  }
  return 0;
}

export function parseDependencies(value: unknown): DependencyRef[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const dependencies: DependencyRef[] = [];
  for (const item of value) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    const name = record.name;
    const version = record.version;
    if (typeof name !== "string" || typeof version !== "string") continue;
    if (name.length === 0 || version.length === 0) continue;
    dependencies.push({ name, version });
  }
  return dependencies.length > 0 ? dependencies : undefined;
}

/** Extract dependencies from an npm lockfile (lockfileVersion 1, 2, or 3). */
export function parseLockfile(json: unknown): DependencyRef[] {
  if (json === null || typeof json !== "object") return [];
  const root = json as Record<string, unknown>;
  const dependencies: DependencyRef[] = [];

  const packages = root.packages;
  if (packages !== null && typeof packages === "object" && !Array.isArray(packages)) {
    const marker = "node_modules/";
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      const last = key.lastIndexOf(marker);
      if (last < 0) continue;
      const name = key.slice(last + marker.length);
      if (name.length === 0 || name.includes("/node_modules/")) continue;
      if (value === null || typeof value !== "object") continue;
      const version = (value as Record<string, unknown>).version;
      if (typeof version === "string" && version.length > 0) {
        dependencies.push({ name, version });
      }
    }
  }

  if (dependencies.length === 0) {
    const legacy = root.dependencies;
    if (legacy !== null && typeof legacy === "object" && !Array.isArray(legacy)) {
      for (const [name, value] of Object.entries(legacy as Record<string, unknown>)) {
        if (value === null || typeof value !== "object") continue;
        const version = (value as Record<string, unknown>).version;
        if (typeof version === "string" && version.length > 0) {
          dependencies.push({ name, version });
        }
      }
    }
  }

  const seen = new Set<string>();
  return dependencies.filter((dependency) => {
    const key = `${dependency.name}@${dependency.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Read `package-lock.json` from a project directory. */
export async function loadNpmLockfile(
  projectDir: string,
): Promise<DependencyRef[] | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(projectDir, "package-lock.json"), "utf8");
  } catch {
    return undefined;
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  const dependencies = parseLockfile(json);
  return dependencies.length > 0 ? dependencies : undefined;
}

/** Pure analyzer: match dependencies against the offline advisory snapshot. */
export function analyzeDependencies(
  dependencies: readonly DependencyRef[],
  advisories: readonly DependencyAdvisory[] = DEPENDENCY_ADVISORIES,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  for (const dependency of dependencies) {
    for (const advisory of advisories) {
      if (advisory.package.toLowerCase() !== dependency.name.toLowerCase()) continue;
      if (compareVersions(dependency.version, advisory.below) >= 0) continue;
      findings.push({
        title: `${dependency.name}@${dependency.version} is vulnerable (${advisory.cve})`,
        affected: { url: `package:${dependency.name}` },
        severity: advisory.severity,
        reproduction: [
          `Read the project's package-lock.json and locate ${dependency.name}@${dependency.version}.`,
        ],
        remediation: `Upgrade ${dependency.name} to ${advisory.below} or newer. ${advisory.summary}.`,
        details: `${advisory.cve}: ${advisory.summary}. Reference: ${advisory.reference}`,
        falsePositiveAnalysis:
          "The installed version is below the patched version recorded in the advisory snapshot.",
      });
    }
  }
  return findings;
}

export const dependenciesCheck: Check = {
  metadata: {
    id: "dependencies",
    toolName: "check_dependencies",
    title: "Dependency advisories (offline snapshot)",
    description:
      "Scans an npm lockfile or a supplied dependency list against a curated offline advisory snapshot.",
    category: "A03",
    categories: ["A03"],
    cwe: "CWE-1104",
    relatedCwes: ["CWE-1329", "CWE-1035"],
    readOnly: true,
    requiresApproval: false,
    severity: "high",
    maxRequests: 0,
    references: [
      "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
      "https://cwe.mitre.org/data/definitions/1104.html",
      "https://osv.dev",
    ],
  },
  async run(ctx, input): Promise<CheckResult> {
    const options = input.options;
    let dependencies = parseDependencies(options?.dependencies);
    if (dependencies === undefined) {
      const projectDir = readOptionString(options, "projectDir") ?? process.cwd();
      dependencies = await loadNpmLockfile(projectDir);
      if (dependencies === undefined) {
        return checkResult(
          ctx,
          [],
          [],
          undefined,
          `no readable package-lock.json found in ${projectDir}`,
        );
      }
    }
    const candidates = analyzeDependencies(dependencies);
    return checkResult(
      ctx,
      materialize(dependenciesCheck.metadata, candidates, []),
      [],
    );
  },
};
