import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { closeSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { createOpencodeClient } from "@opencode-ai/sdk";
import { config } from "./config.js";

/** Provider-level prompt for the direct-question agent. Logged in transcripts. */
export const ASK_AGENT_PROMPT = "Answer the user directly and concisely. Do not use tools.";

/** Provider-level prompt for the pentest planner agent. Logged in transcripts. */
export const PLANNER_AGENT_PROMPT =
  "You are the Anbu pentest planner. Return only the structured JSON plan described in the user prompt. Do not use tools.";

/** Inline OpenCode configuration: Ollama provider plus the two tool-less agents. */
const OPENCODE_CONFIG = {
  model: `ollama/${config.model}`,
  provider: {
    ollama: {
      npm: "@ai-sdk/openai-compatible",
      name: "Ollama (Docker)",
      options: {
        baseURL: config.ollamaBaseUrl,
        // CPU-bound Ollama turns can exceed the 5-minute default timeout,
        // which aborts the request with "fetch failed" mid-generation.
        timeout: false,
      },
      models: {
        [config.model]: { name: config.model },
      },
    },
  },
  agent: {
    ask: {
      model: `ollama/${config.model}`,
      mode: "primary",
      prompt: ASK_AGENT_PROMPT,
      tools: { "*": false },
    },
    planner: {
      model: `ollama/${config.model}`,
      mode: "primary",
      prompt: PLANNER_AGENT_PROMPT,
      tools: { "*": false },
    },
  },
} as const;

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const READY_PATTERN = /^opencode server listening on (https?:\/\/\S+)/m;

export interface OpencodeHandle {
  client: ReturnType<typeof createOpencodeClient>;
  server: { url: string; close(): void };
}

function isLinuxExecutable(path: string): boolean {
  try {
    const real = realpathSync(path);
    const fd = openSync(real, "r");
    try {
      const magic = Buffer.alloc(ELF_MAGIC.length);
      const read = readSync(fd, magic, 0, ELF_MAGIC.length, 0);
      return read === ELF_MAGIC.length && ELF_MAGIC.every((byte, i) => magic[i] === byte);
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
}

function isExecutableFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * The dev container bind-mounts the host workspace, so `npm run` can put a
 * host `node_modules/.bin` (for example a Windows `opencode.exe`) ahead of the
 * Linux binary installed in the image. Resolve an executable matching the
 * current platform before spawning the server.
 */
function findOpencodeBinary(): string {
  if (process.platform === "linux") {
    const candidates = ["/app/node_modules/.bin/opencode", "/usr/local/bin/opencode", "/usr/bin/opencode"];
    for (const dir of (process.env.PATH ?? "").split(":")) {
      if (dir.length > 0) candidates.push(join(dir, "opencode"));
    }
    for (const candidate of candidates) {
      if (isLinuxExecutable(candidate)) return realpathSync(candidate);
    }
    return "opencode";
  }

  if (process.platform === "win32") {
    // `spawn` without a shell cannot execute the npm shim scripts
    // (`opencode.cmd` / `opencode.ps1`), so resolve the real `opencode.exe`
    // installed by the npm package inside the global prefix.
    const candidates: string[] = [];
    const npmPrefix = process.env.APPDATA === undefined ? undefined : join(process.env.APPDATA, "npm");
    if (npmPrefix !== undefined) {
      candidates.push(join(npmPrefix, "node_modules", "opencode-ai", "bin", "opencode.exe"));
      candidates.push(join(npmPrefix, "opencode.exe"));
    }
    for (const dir of (process.env.PATH ?? "").split(";")) {
      const trimmed = dir.trim().replace(/^"|"$/g, "");
      if (trimmed.length > 0) {
        candidates.push(join(trimmed, "opencode.exe"));
        candidates.push(join(trimmed, "node_modules", "opencode-ai", "bin", "opencode.exe"));
      }
    }
    for (const candidate of candidates) {
      if (isExecutableFile(candidate)) return candidate;
    }
  }

  return "opencode";
}

function waitForServer(proc: ChildProcess, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    let settled = false;

    const cleanup = (): void => {
      clearTimeout(timer);
      proc.stdout?.off("data", onData);
      proc.stderr?.off("data", onData);
      proc.off("error", onError);
      proc.off("exit", onExit);
    };
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      cleanup();
      action();
    };
    const onData = (chunk: Buffer): void => {
      output += chunk.toString();
      const match = output.match(READY_PATTERN);
      if (match !== null) finish(() => resolve(match[1]));
    };
    const onError = (err: Error): void => finish(() => reject(err));
    const onExit = (code: number | null): void =>
      finish(() => {
        const detail = output.trim();
        reject(
          new Error(
            `OpenCode server exited with code ${code}${detail.length > 0 ? `\nServer output: ${detail}` : ""}`,
          ),
        );
      });
    const timer = setTimeout(() => {
      finish(() => {
        proc.kill();
        const detail = output.trim();
        reject(
          new Error(
            `Timeout waiting for the OpenCode server after ${timeoutMs}ms${detail.length > 0 ? `\nServer output: ${detail}` : ""}`,
          ),
        );
      });
    }, timeoutMs);

    proc.stdout?.on("data", onData);
    proc.stderr?.on("data", onData);
    proc.once("error", onError);
    proc.once("exit", onExit);
  });
}

/**
 * Starts the OpenCode server and returns a typed client. The server is spawned
 * with an explicit binary so a host-mounted Windows `node_modules` cannot
 * shadow the Linux CLI in the dev container. The Ollama provider configuration
 * is passed inline so the application does not depend on a host config file.
 */
export async function startOpencode(): Promise<OpencodeHandle> {
  const binary = findOpencodeBinary();
  const args = [
    "serve",
    `--hostname=${config.opencodeHost}`,
    `--port=${String(config.opencodePort)}`,
  ];
  const proc = spawn(binary, args, {
    env: {
      ...process.env,
      OPENCODE_CONFIG_CONTENT: JSON.stringify(OPENCODE_CONFIG),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const url = await waitForServer(proc, 30_000);
    const client = createOpencodeClient({ baseUrl: url });
    return {
      client,
      server: {
        url,
        close() {
          if (proc.exitCode === null && proc.signalCode === null) proc.kill();
        },
      },
    };
  } catch (err) {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill();
    throw err;
  }
}
