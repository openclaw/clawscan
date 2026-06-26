import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { Type, type Static } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_OUTPUT_DIR = path.join(homedir(), ".openclaw", "clawscan");

const ClawScanPluginConfigSchema = Type.Object(
  {
    binary: Type.Optional(
      Type.String({
        description: "ClawScan executable path or command name.",
      }),
    ),
    defaultProfile: Type.Optional(
      Type.String({
        description: "Profile to use when a tool call does not specify profile or scanners.",
      }),
    ),
    defaultConfig: Type.Optional(
      Type.String({
        description: "Default .clawscan.yml path.",
      }),
    ),
    defaultScanners: Type.Optional(
      Type.Array(Type.String(), {
        description: "Scanner ids to use when a tool call does not specify scanners or profile.",
      }),
    ),
    defaultOutputDir: Type.Optional(
      Type.String({
        description: "Directory where scan artifacts are written.",
      }),
    ),
    json: Type.Optional(
      Type.Boolean({
        description: "Pass --json by default so ClawScan emits structured output.",
      }),
    ),
    sandbox: Type.Optional(
      Type.Union([Type.Literal("docker"), Type.Literal("off")], {
        description: "ClawScan sandbox mode.",
      }),
    ),
    sandboxImage: Type.Optional(
      Type.String({
        description: "Docker image for ClawScan sandboxed scanner execution.",
      }),
    ),
    sandboxEnv: Type.Optional(
      Type.Array(Type.String(), {
        description: "Environment variable names to allow through the ClawScan sandbox.",
      }),
    ),
    timeoutMs: Type.Optional(
      Type.Number({
        description: "Maximum scan runtime in milliseconds.",
        minimum: 1000,
      }),
    ),
  },
  { additionalProperties: false },
);

const ClawScanToolParamsSchema = Type.Object(
  {
    target: Type.Optional(
      Type.String({
        description: "Skill file or directory to scan. Omit only when scanning ./skills.",
      }),
    ),
    profile: Type.Optional(
      Type.String({
        description: "ClawScan profile, such as clawhub or skills-sh.",
      }),
    ),
    config: Type.Optional(
      Type.String({
        description: "Path to a .clawscan.yml file.",
      }),
    ),
    scanners: Type.Optional(
      Type.Array(Type.String(), {
        description: "Scanner ids to run, such as skillspector or clawscan-static.",
      }),
    ),
    output: Type.Optional(
      Type.String({
        description: "Artifact path. Defaults under ~/.openclaw/clawscan.",
      }),
    ),
    json: Type.Optional(
      Type.Boolean({
        description: "Pass --json for structured stdout.",
      }),
    ),
    sandbox: Type.Optional(Type.Union([Type.Literal("docker"), Type.Literal("off")])),
    sandboxImage: Type.Optional(Type.String()),
    sandboxEnv: Type.Optional(
      Type.Array(Type.String(), {
        description: "Environment variable names to allow through the ClawScan sandbox.",
      }),
    ),
    timeoutMs: Type.Optional(Type.Number({ minimum: 1000 })),
  },
  { additionalProperties: false },
);

type ClawScanPluginConfig = Static<typeof ClawScanPluginConfigSchema>;
type ClawScanToolParams = Static<typeof ClawScanToolParamsSchema>;

export type ClawScanInvocation = {
  command: string;
  args: string[];
  outputPath: string;
  timeoutMs: number;
};

type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

type ScanSummary = {
  schemaVersion?: string;
  profile?: string;
  target?: string;
  scannerCompleted?: number;
  scannerFailed?: number;
  scannerSkipped?: number;
  scanners?: Record<string, string>;
  judgeStatus?: string;
  verdict?: string;
};

function cleanOptionalString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function cleanStringList(value: readonly string[] | undefined): string[] {
  return [...new Set((value ?? []).map((item) => item.trim()).filter(Boolean))];
}

function expandHomePath(value: string): string {
  if (value === "~") {
    return homedir();
  }
  if (value.startsWith("~/")) {
    return path.join(homedir(), value.slice(2));
  }
  return value;
}

function assertEnvNames(names: readonly string[]): void {
  const invalid = names.find((name) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
  if (invalid) {
    throw new Error(`Invalid sandbox env var name: ${invalid}`);
  }
}

function slugForPath(value: string | undefined): string {
  const base = value ? path.basename(value) : "skills";
  return base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "scan";
}

function createDefaultOutputPath(params: {
  outputDir: string;
  target?: string;
  profile?: string;
  scanners: readonly string[];
  now?: Date;
}): string {
  const targetSlug = slugForPath(params.target);
  const modeSlug = (params.profile ?? params.scanners.join("-")) || "clawscan";
  const timestamp = (params.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  return path.join(params.outputDir, `${targetSlug}-${modeSlug}-${timestamp}.json`);
}

export function buildClawScanInvocation(
  params: ClawScanToolParams,
  config: ClawScanPluginConfig,
  options: { now?: Date } = {},
): ClawScanInvocation {
  const configuredBinary = cleanOptionalString(config.binary);
  const command = configuredBinary ? expandHomePath(configuredBinary) : "clawscan";
  const target = cleanOptionalString(params.target);
  const requestedProfile = cleanOptionalString(params.profile);
  const requestedScanners =
    params.scanners !== undefined ? cleanStringList(params.scanners) : undefined;
  const requestedConfigPath =
    cleanOptionalString(params.config) ?? cleanOptionalString(config.defaultConfig);
  const configPath = requestedConfigPath ? expandHomePath(requestedConfigPath) : undefined;
  const profile =
    requestedProfile ??
    (requestedScanners === undefined ? cleanOptionalString(config.defaultProfile) : undefined);
  const scanners =
    requestedScanners ??
    (requestedProfile === undefined ? cleanStringList(config.defaultScanners) : []);
  const sandbox = params.sandbox ?? config.sandbox;
  const sandboxImage = cleanOptionalString(params.sandboxImage) ?? cleanOptionalString(config.sandboxImage);
  const sandboxEnv = [
    ...cleanStringList(config.sandboxEnv),
    ...cleanStringList(params.sandboxEnv),
  ];
  assertEnvNames(sandboxEnv);

  if (!target && !profile && !configPath && scanners.length === 0) {
    throw new Error(
      "clawscan_scan requires a target, profile, config, or scanner. Configure a defaultProfile or pass one in the tool call.",
    );
  }

  const requestedOutputPath = cleanOptionalString(params.output);
  const configuredOutputDir = cleanOptionalString(config.defaultOutputDir);
  const outputPath =
    (requestedOutputPath ? expandHomePath(requestedOutputPath) : undefined) ??
    createDefaultOutputPath({
      outputDir: configuredOutputDir ? expandHomePath(configuredOutputDir) : DEFAULT_OUTPUT_DIR,
      target,
      profile,
      scanners,
      now: options.now,
    });

  const args: string[] = [];
  if (target) {
    args.push(target);
  }
  if (configPath) {
    args.push("--config", configPath);
  }
  if (profile) {
    args.push("--profile", profile);
  }
  for (const scanner of scanners) {
    args.push("--scanner", scanner);
  }
  args.push("--output", outputPath);
  if (params.json ?? config.json ?? true) {
    args.push("--json");
  }
  if (sandbox) {
    args.push("--sandbox", sandbox);
  }
  if (sandboxImage) {
    args.push("--sandbox-image", sandboxImage);
  }
  for (const name of sandboxEnv) {
    args.push("--sandbox-env", name);
  }

  const timeoutMs = params.timeoutMs ?? config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return { command, args, outputPath, timeoutMs };
}

function runCommand(
  invocation: ClawScanInvocation,
  options: { signal?: AbortSignal } = {},
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      env: process.env,
      signal: options.signal,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`clawscan timed out after ${invocation.timeoutMs}ms`));
    }, invocation.timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({
        exitCode: code ?? 1,
        stdout,
        stderr,
      });
    });
  });
}

function summarizeArtifact(raw: unknown): ScanSummary | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const artifact = raw as Record<string, unknown>;
  const scannersRaw =
    artifact.scanners && typeof artifact.scanners === "object"
      ? (artifact.scanners as Record<string, Record<string, unknown>>)
      : undefined;
  const scanners = scannersRaw
    ? Object.fromEntries(
        Object.entries(scannersRaw).map(([name, result]) => [
          name,
          typeof result.status === "string" ? result.status : "unknown",
        ]),
      )
    : undefined;
  const targetRaw = artifact.target;
  const target =
    targetRaw && typeof targetRaw === "object" && typeof (targetRaw as { input?: unknown }).input === "string"
      ? (targetRaw as { input: string }).input
      : undefined;
  const judgeRaw = artifact.judge;
  const judge =
    judgeRaw && typeof judgeRaw === "object" ? (judgeRaw as Record<string, unknown>) : undefined;

  return {
    schemaVersion: typeof artifact.schemaVersion === "string" ? artifact.schemaVersion : undefined,
    profile: typeof artifact.profile === "string" ? artifact.profile : undefined,
    target,
    scannerCompleted:
      typeof artifact.scannerCompleted === "number" ? artifact.scannerCompleted : undefined,
    scannerFailed: typeof artifact.scannerFailed === "number" ? artifact.scannerFailed : undefined,
    scannerSkipped: typeof artifact.scannerSkipped === "number" ? artifact.scannerSkipped : undefined,
    scanners,
    judgeStatus: typeof judge?.status === "string" ? judge.status : undefined,
    verdict: typeof judge?.verdict === "string" ? judge.verdict : undefined,
  };
}

export function summarizeClawScanJson(stdout: string): ScanSummary | undefined {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    return summarizeArtifact(JSON.parse(trimmed));
  } catch {
    return undefined;
  }
}

export default defineToolPlugin({
  id: "clawscan",
  name: "ClawScan",
  description: "Run ClawScan security scans from OpenClaw.",
  configSchema: ClawScanPluginConfigSchema,
  tools: (tool) => [
    tool({
      name: "clawscan_scan",
      label: "ClawScan Scan",
      description: "Run ClawScan against a skill target with a safe argv-only CLI invocation.",
      parameters: ClawScanToolParamsSchema,
      execute: async (params, config, context) => {
        const invocation = buildClawScanInvocation(params, config);
        await mkdir(path.dirname(invocation.outputPath), { recursive: true });
        context.onUpdate?.({
          content: [],
          details: undefined,
          progress: {
            text: `Running ClawScan -> ${invocation.outputPath}`,
            visibility: "channel",
            privacy: "public",
          },
        });
        const result = await runCommand(invocation, { signal: context.signal });
        const summary = summarizeClawScanJson(result.stdout);
        return {
          ok: result.exitCode === 0,
          exitCode: result.exitCode,
          artifactPath: invocation.outputPath,
          command: invocation.command,
          args: invocation.args,
          summary,
          stderrPresent: result.stderr.trim().length > 0,
        };
      },
    }),
  ],
});
