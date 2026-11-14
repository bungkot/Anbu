import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { config, ollamaRoot } from "./config.js";
import { AuditLog } from "./audit/log.js";
import { ensureModel, listModels, waitForOllama } from "./health.js";
import { startOpencode } from "./opencode.js";
import { intake } from "./intake.js";
import { RateLimiter } from "./guardrails/rate-limit.js";
import { runRecon } from "./recon.js";
import type { AttackSurfaceSummary } from "./recon.js";

async function doctor(): Promise<void> {
  console.log(`Ollama root : ${ollamaRoot()}`);
  console.log(`Base URL    : ${config.ollamaBaseUrl}`);
  console.log(`Model       : ${config.model}`);
  await waitForOllama(15_000);
  console.log(`Models      : ${(await listModels()).join(", ") || "(empty)"}`);
  await ensureModel();
  console.log("OK: Ollama is ready and the model is available.");
}

async function ask(prompt: string): Promise<void> {
  await waitForOllama();
  await ensureModel();

  const { client, server } = await startOpencode();
  try {
    const session = await client.session.create({ body: { title: "ask" } });
    if (!session.data) {
      throw new Error(`Failed to create session: ${JSON.stringify(session.error)}`);
    }

    const result = await client.session.prompt({
      path: { id: session.data.id },
      body: {
        model: { providerID: "ollama", modelID: config.model },
        agent: "ask",
        tools: { "*": false },
        parts: [{ type: "text", text: prompt }],
      },
    });
    if (!result.data) {
      throw new Error(`Prompt failed: ${JSON.stringify(result.error)}`);
    }

    const answer = result.data.parts
      .filter((part) => part.type === "text")
      .map((part) => part.text)
      .join("\n")
      .trim();
    if (!answer) throw new Error("OpenCode returned an empty response from Ollama.");
    console.log(answer);
  } finally {
    server.close();
  }
}

function parseScopeArg(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--scope" && args[i + 1] !== undefined) return args[i + 1];
    if (args[i].startsWith("--scope=")) return args[i].slice("--scope=".length);
  }
  return config.scopeFile || undefined;
}

async function intakeCommand(args: string[]): Promise<void> {
  const scopePath = parseScopeArg(args);
  if (scopePath === undefined) throw new Error("Usage: intake --scope <file>");

  const result = await intake(scopePath);
  if (!result.ok) {
    console.error("Refusing to start:");
    for (const error of result.errors) console.error(`  - ${error}`);
    process.exitCode = 1;
    return;
  }

  const targets = result.scope.targets
    .map((target) => {
      const scheme = target.scheme ?? "https";
      const port =
        target.port === undefined || target.port === (scheme === "https" ? 443 : 80)
          ? ""
          : `:${target.port}`;
      return `${scheme}://${target.host}${port}`;
    })
    .join(", ");

  console.log(`Scope accepted: ${result.scope.name}`);
  console.log(`  Targets      : ${targets}`);
  console.log(`  Test classes : ${result.scope.testClasses.join(", ")}`);
  console.log(`  Read-only    : ${result.scope.readOnly}`);
  console.log(
    `  Authorization : ${result.authorization.reference} (valid until ${result.authorization.expiresAt})`,
  );
}

interface ReconArgs {
  scopePath?: string;
  startUrls: string[];
  maxDepth: number;
  maxUrls: number;
  json: boolean;
}

function parseReconArgs(args: string[]): ReconArgs {
  const parsed: ReconArgs = {
    startUrls: [],
    maxDepth: 2,
    maxUrls: 50,
    json: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const value = args[i + 1];
    if (arg === "--scope" && value !== undefined) {
      parsed.scopePath = value;
      i += 1;
    } else if (arg.startsWith("--scope=")) {
      parsed.scopePath = arg.slice("--scope=".length);
    } else if (arg === "--start-url" && value !== undefined) {
      parsed.startUrls.push(value);
      i += 1;
    } else if (arg.startsWith("--start-url=")) {
      parsed.startUrls.push(arg.slice("--start-url=".length));
    } else if (arg === "--max-depth" && value !== undefined) {
      parsed.maxDepth = Number(value);
      i += 1;
    } else if (arg.startsWith("--max-depth=")) {
      parsed.maxDepth = Number(arg.slice("--max-depth=".length));
    } else if (arg === "--max-urls" && value !== undefined) {
      parsed.maxUrls = Number(value);
      i += 1;
    } else if (arg.startsWith("--max-urls=")) {
      parsed.maxUrls = Number(arg.slice("--max-urls=".length));
    } else if (arg === "--json") {
      parsed.json = true;
    } else {
      throw new Error(`unknown recon argument: ${arg}`);
    }
  }
  return parsed;
}

function printReconSummary(summary: AttackSurfaceSummary): void {
  console.log(`Targets     : ${summary.targets.join(", ")}`);
  console.log(`Start URLs  : ${summary.startUrls.join(", ")}`);
  console.log(
    `Requests    : ${summary.requests} (maxDepth ${summary.maxDepth}, maxUrls ${summary.maxUrls})`,
  );
  console.log(`Truncated   : ${summary.truncated ? "yes" : "no"}`);

  console.log(`URLs (${summary.urls.length}):`);
  for (const url of summary.urls) console.log(`  - ${url}`);

  console.log(`Forms (${summary.forms.length}):`);
  for (const form of summary.forms) {
    const parameters = form.parameters.length > 0 ? ` (${form.parameters.join(", ")})` : "";
    console.log(`  - ${form.method} ${form.action}${parameters}`);
  }

  console.log(`Assets (${summary.assets.length}):`);
  for (const asset of summary.assets) console.log(`  - ${asset.type} ${asset.url}`);

  console.log(`Technologies (${summary.technologies.length}):`);
  for (const marker of summary.technologies) {
    console.log(`  - ${marker.name}: ${marker.evidence}`);
  }

  console.log(`Blocked (${summary.blocked.length}):`);
  for (const block of summary.blocked) console.log(`  - ${block.url}: ${block.reason}`);
}

async function reconCommand(args: string[]): Promise<void> {
  const parsed = parseReconArgs(args);
  const scopePath = parsed.scopePath ?? (config.scopeFile || undefined);
  if (scopePath === undefined) {
    throw new Error(
      "Usage: recon --scope <file> [--start-url <url>] [--max-depth N] [--max-urls N] [--json]",
    );
  }

  const result = await intake(scopePath);
  if (!result.ok) {
    console.error("Refusing to start:");
    for (const error of result.errors) console.error(`  - ${error}`);
    process.exitCode = 1;
    return;
  }

  const scope = result.scope;
  const rateLimiter = new RateLimiter({
    requestsPerSecondPerHost:
      scope.policy?.requestsPerSecondPerHost ?? config.requestsPerSecondPerHost,
    maxRequests: scope.policy?.maxRequests ?? config.maxRequests,
  });
  const audit = new AuditLog(join(config.evidenceDir, "audit.log"), `recon-${randomUUID()}`);

  const recon = await runRecon({
    scope,
    startUrls: parsed.startUrls.length > 0 ? parsed.startUrls : undefined,
    maxDepth: parsed.maxDepth,
    maxUrls: parsed.maxUrls,
    rateLimiter,
    audit,
  });

  if (!recon.ok || recon.summary === undefined) {
    console.error(`recon failed: ${recon.error ?? "unknown error"}`);
    process.exitCode = 1;
    return;
  }

  if (parsed.json) {
    console.log(
      JSON.stringify(
        {
          scope: recon.scopeName,
          authorization: scope.authorization.reference,
          summary: recon.summary,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Recon: ${recon.scopeName}`);
  printReconSummary(recon.summary);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "doctor":
      return doctor();
    case "ask": {
      const prompt = rest.join(" ").trim();
      if (!prompt) throw new Error('Usage: ask "your question"');
      return ask(prompt);
    }
    case "intake":
      return intakeCommand(rest);
    case "recon":
      return reconCommand(rest);
    default:
      console.log(
        'Commands: doctor | ask "<prompt>" | intake --scope <file> | recon --scope <file>',
      );
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
