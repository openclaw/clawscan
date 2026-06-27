import { spawn } from "node:child_process";
import { mkdir, open } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { Type, type Static } from "typebox";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_OUTPUT_DIR = path.join(homedir(), ".openclaw", "clawscan");
const MAX_CAPTURED_STDIO_BYTES = 256 * 1024;
const MAX_ARTIFACT_SUMMARY_BYTES = 2 * 1024 * 1024;
const MAX_HOOK_FINDINGS = 20;
const ISSUE_ARRAY_KEYS = new Set(["alerts", "findings", "issues", "vulnerabilities"]);

const FindingSeveritySchema = Type.Union([
  Type.Literal("low"),
  Type.Literal("medium"),
  Type.Literal("high"),
  Type.Literal("critical"),
]);

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
    beforeInstall: Type.Optional(
      Type.Object(
        {
          enabled: Type.Optional(
            Type.Boolean({
              description: "Run ClawScan from the before_install hook for skill installs.",
            }),
          ),
          blockSeverity: Type.Optional(
            Type.Union([Type.Literal("never"), FindingSeveritySchema], {
              description:
                "Minimum ClawScan finding severity that blocks a skill install. Defaults to high.",
            }),
          ),
        },
        { additionalProperties: false },
      ),
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
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
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

type ClawScanIssue = {
  scanner: string;
  ruleId: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  file: string;
  line: number;
};

type ClawScanExecutionFailure = {
  ruleId: string;
  label: string;
  message: string;
  file: string;
  line: number;
};

type BeforeInstallEvent = {
  targetType?: unknown;
  targetName?: unknown;
  sourcePath?: unknown;
  request?: {
    kind?: unknown;
    mode?: unknown;
    requestedSpecifier?: unknown;
  };
};

type BeforeInstallFinding = {
  ruleId: string;
  severity: "info" | "warn" | "critical";
  file: string;
  line: number;
  message: string;
};

type BeforeInstallResult = {
  findings?: BeforeInstallFinding[];
  block?: boolean;
  blockReason?: string;
};

type ArtifactReadResult =
  | { ok: true; artifact: unknown }
  | { ok: false; reason: string };

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

function resolveSandboxEnv(params: {
  configured: readonly string[];
  requested: readonly string[];
}): string[] {
  assertEnvNames(params.configured);
  assertEnvNames(params.requested);
  if (params.requested.length === 0) {
    return [...params.configured];
  }
  const allowed = new Set(params.configured);
  const denied = params.requested.filter((name) => !allowed.has(name));
  if (denied.length > 0) {
    throw new Error(
      `sandboxEnv may only select names already allowed by plugin config: ${denied.join(", ")}`,
    );
  }
  return [...params.requested];
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

function createBeforeInstallOutputPath(params: {
  outputDir: string;
  targetName: string;
  profile?: string;
  scanners: readonly string[];
  now?: Date;
}): string {
  const targetSlug = slugForPath(params.targetName);
  const modeSlug = (params.profile ?? params.scanners.join("-")) || "clawscan";
  const timestamp = (params.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  return path.join(params.outputDir, `${targetSlug}-before-install-${modeSlug}-${timestamp}.json`);
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
  const sandboxEnv = resolveSandboxEnv({
    configured: cleanStringList(config.sandboxEnv),
    requested: cleanStringList(params.sandboxEnv),
  });

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
  if (params.json ?? config.json ?? false) {
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

export function buildBeforeInstallClawScanInvocation(
  event: BeforeInstallEvent,
  config: ClawScanPluginConfig,
  options: { now?: Date } = {},
): ClawScanInvocation | undefined {
  if (event.targetType !== "skill" || event.request?.kind !== "skill-install") {
    return undefined;
  }
  if (config.beforeInstall?.enabled === false) {
    return undefined;
  }
  const sourcePath = typeof event.sourcePath === "string" ? event.sourcePath : undefined;
  if (!sourcePath) {
    return undefined;
  }
  const targetName = typeof event.targetName === "string" ? event.targetName : sourcePath;
  const scanners = cleanStringList(config.defaultScanners);
  const profile = cleanOptionalString(config.defaultProfile);
  const configPath = cleanOptionalString(config.defaultConfig);
  if (scanners.length === 0 && !profile && !configPath) {
    return undefined;
  }
  const configuredOutputDir = cleanOptionalString(config.defaultOutputDir);
  const outputDir = configuredOutputDir ? expandHomePath(configuredOutputDir) : DEFAULT_OUTPUT_DIR;
  return buildClawScanInvocation(
    {
      target: sourcePath,
      output: createBeforeInstallOutputPath({
        outputDir,
        targetName,
        profile,
        scanners,
        now: options.now,
      }),
    },
    config,
    options,
  );
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
    let stdoutTruncated = false;
    let stderrTruncated = false;
    const appendBounded = (current: string, chunk: string, stream: "stdout" | "stderr") => {
      const remaining = MAX_CAPTURED_STDIO_BYTES - Buffer.byteLength(current);
      if (remaining <= 0) {
        if (stream === "stdout") {
          stdoutTruncated = true;
        } else {
          stderrTruncated = true;
        }
        return current;
      }
      const chunkBytes = Buffer.byteLength(chunk);
      if (chunkBytes <= remaining) {
        return current + chunk;
      }
      if (stream === "stdout") {
        stdoutTruncated = true;
      } else {
        stderrTruncated = true;
      }
      return current + Buffer.from(chunk).subarray(0, remaining).toString("utf8");
    };
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`clawscan timed out after ${invocation.timeoutMs}ms`));
    }, invocation.timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk, "stdout");
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk, "stderr");
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
        stdoutTruncated,
        stderrTruncated,
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

function normalizeIssueSeverity(value: unknown): ClawScanIssue["severity"] {
  const severity = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return "low";
}

function normalizeJudgeVerdict(value: unknown): "clean" | "suspicious" | "malicious" | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const result = value as Record<string, unknown>;
  for (const key of ["verdict", "prediction", "status"]) {
    const raw = result[key];
    const verdict = typeof raw === "string" ? raw.trim().toLowerCase() : "";
    if (verdict === "benign" || verdict === "clean" || verdict === "ok") {
      return "clean";
    }
    if (verdict === "suspicious" || verdict === "review" || verdict === "needs_review" || verdict === "needs review") {
      return "suspicious";
    }
    if (verdict === "malicious") {
      return "malicious";
    }
  }
  return undefined;
}

function findingSeverity(issueSeverity: ClawScanIssue["severity"]): BeforeInstallFinding["severity"] {
  if (issueSeverity === "critical" || issueSeverity === "high") {
    return "critical";
  }
  if (issueSeverity === "medium") {
    return "warn";
  }
  return "info";
}

function severityRank(severity: "never" | ClawScanIssue["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    case "never":
      return Number.POSITIVE_INFINITY;
  }
}

function normalizeIssue(
  scanner: string,
  value: unknown,
  severityFallback?: ClawScanIssue["severity"],
): ClawScanIssue | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const issue = value as Record<string, unknown>;
  const location =
    issue.location && typeof issue.location === "object"
      ? (issue.location as Record<string, unknown>)
      : undefined;
  const ruleId =
    cleanOptionalString(typeof issue.id === "string" ? issue.id : undefined) ??
    cleanOptionalString(typeof issue.ruleId === "string" ? issue.ruleId : undefined) ??
    `${scanner}.finding`;
  const category = cleanOptionalString(typeof issue.category === "string" ? issue.category : undefined);
  const title = cleanOptionalString(typeof issue.title === "string" ? issue.title : undefined);
  const description = cleanOptionalString(
    typeof issue.description === "string" ? issue.description : undefined,
  );
  const explanation = cleanOptionalString(
    typeof issue.explanation === "string" ? issue.explanation : undefined,
  );
  const finding = cleanOptionalString(typeof issue.finding === "string" ? issue.finding : undefined);
  const evidence = cleanOptionalString(typeof issue.evidence === "string" ? issue.evidence : undefined);
  const detail = explanation ?? description ?? finding ?? evidence;
  const message = [category ?? title, detail].filter(Boolean).join(": ") || ruleId;
  const file =
    cleanOptionalString(typeof location?.file === "string" ? location.file : undefined) ??
    cleanOptionalString(typeof issue.file === "string" ? issue.file : undefined) ??
    cleanOptionalString(typeof issue.path === "string" ? issue.path : undefined) ??
    ".";
  const line =
    typeof location?.start_line === "number" && Number.isFinite(location.start_line)
      ? Math.max(1, Math.floor(location.start_line))
      : typeof issue.line === "number" && Number.isFinite(issue.line)
        ? Math.max(1, Math.floor(issue.line))
        : 1;
  return {
    scanner,
    ruleId: `${scanner}.${ruleId}`,
    severity: issue.severity === undefined ? (severityFallback ?? "low") : normalizeIssueSeverity(issue.severity),
    message,
    file,
    line,
  };
}

function reportSeverityFallback(raw: Record<string, unknown> | undefined): ClawScanIssue["severity"] | undefined {
  if (!raw) {
    return undefined;
  }
  const direct = typeof raw.severity === "string" ? raw.severity : undefined;
  if (direct) {
    return normalizeIssueSeverity(direct);
  }
  const riskAssessment =
    raw.risk_assessment && typeof raw.risk_assessment === "object"
      ? (raw.risk_assessment as Record<string, unknown>)
      : undefined;
  const riskSeverity =
    typeof riskAssessment?.severity === "string" ? riskAssessment.severity : undefined;
  if (riskSeverity) {
    return normalizeIssueSeverity(riskSeverity);
  }
  const recommendation = typeof raw.recommendation === "string" ? raw.recommendation.trim().toLowerCase() : "";
  if (recommendation === "do_not_install" || recommendation === "block") {
    return "high";
  }
  if (recommendation === "caution" || recommendation === "review") {
    return "medium";
  }
  return undefined;
}

function collectIssueArrayValues(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectIssueArrayValues(item));
  }
  if (!value || typeof value !== "object") {
    return [];
  }
  const issues: unknown[] = [];
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (ISSUE_ARRAY_KEYS.has(key.toLowerCase()) && Array.isArray(nested)) {
      issues.push(...nested);
      continue;
    }
    issues.push(...collectIssueArrayValues(nested));
  }
  return issues;
}

export function collectClawScanIssues(raw: unknown): ClawScanIssue[] {
  if (!raw || typeof raw !== "object") {
    return [];
  }
  const artifact = raw as Record<string, unknown>;
  const issues: ClawScanIssue[] = [];
  if (Array.isArray(artifact.runs)) {
    for (const run of artifact.runs) {
      issues.push(...collectClawScanIssues(run));
    }
  }
  const judge =
    artifact.judge && typeof artifact.judge === "object"
      ? (artifact.judge as Record<string, unknown>)
      : undefined;
  const judgeVerdict = normalizeJudgeVerdict(judge?.result);
  if (judgeVerdict === "suspicious" || judgeVerdict === "malicious") {
    issues.push({
      scanner: "judge",
      ruleId: `clawscan.judge_${judgeVerdict}`,
      severity: judgeVerdict === "malicious" ? "critical" : "high",
      message: `judge verdict: ${judgeVerdict}`,
      file: ".",
      line: 1,
    });
  }
  const scannersRaw =
    artifact.scanners && typeof artifact.scanners === "object"
      ? (artifact.scanners as Record<string, unknown>)
      : undefined;
  if (!scannersRaw) {
    return issues;
  }
  for (const [scanner, scannerResult] of Object.entries(scannersRaw)) {
    if (!scannerResult || typeof scannerResult !== "object") {
      continue;
    }
    const raw = (scannerResult as Record<string, unknown>).raw;
    const rawRecord = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : undefined;
    const severityFallback = reportSeverityFallback(rawRecord);
    for (const issue of collectIssueArrayValues(rawRecord)) {
      const normalized = normalizeIssue(scanner, issue, severityFallback);
      if (normalized) {
        issues.push(normalized);
      }
    }
  }
  return issues;
}

function collectClawScanExecutionFailures(raw: unknown): ClawScanExecutionFailure[] {
  if (!raw || typeof raw !== "object") {
    return [];
  }
  const artifact = raw as Record<string, unknown>;
  const failures: ClawScanExecutionFailure[] = [];
  if (Array.isArray(artifact.runs)) {
    for (const run of artifact.runs) {
      failures.push(...collectClawScanExecutionFailures(run));
    }
  }
  if (Array.isArray(artifact.errors)) {
    for (const value of artifact.errors) {
      if (!value || typeof value !== "object") {
        continue;
      }
      const error = value as Record<string, unknown>;
      const profile = cleanOptionalString(
        typeof error.profile === "string" ? error.profile : undefined,
      );
      const message =
        cleanOptionalString(typeof error.error === "string" ? error.error : undefined) ??
        "batch profile failed without an error message";
      failures.push({
        ruleId: "clawscan.batch_error",
        label: profile ? `profile ${profile}` : "ClawScan batch",
        message,
        file: ".",
        line: 1,
      });
    }
  }
  if (artifact.judge && typeof artifact.judge === "object") {
    const judge = artifact.judge as Record<string, unknown>;
    const status = typeof judge.status === "string" ? judge.status.trim().toLowerCase() : "";
    if (status !== "completed") {
      const message =
        cleanOptionalString(typeof judge.error === "string" ? judge.error : undefined) ??
        (status ? `judge status was ${status}` : "judge did not report a completed status");
      failures.push({
        ruleId: "clawscan.judge_failed",
        label: "judge",
        message,
        file: ".",
        line: 1,
      });
    }
  }
  const scannersRaw =
    artifact.scanners && typeof artifact.scanners === "object"
      ? (artifact.scanners as Record<string, unknown>)
      : undefined;
  if (!scannersRaw) {
    return failures;
  }
  for (const [scanner, scannerResult] of Object.entries(scannersRaw)) {
    if (!scannerResult || typeof scannerResult !== "object") {
      continue;
    }
    const result = scannerResult as Record<string, unknown>;
    const status = typeof result.status === "string" ? result.status.trim().toLowerCase() : "";
    if (status !== "failed") {
      continue;
    }
    const message =
      cleanOptionalString(typeof result.error === "string" ? result.error : undefined) ??
      "scanner failed without an error message";
    failures.push({
      ruleId: `${scanner}.scanner_failed`,
      label: `${scanner} scanner`,
      message,
      file: ".",
      line: 1,
    });
  }
  return failures;
}

function summarizeBlockReason(params: {
  artifactPath: string;
  blockingIssues: readonly ClawScanIssue[];
}): string {
  const first = params.blockingIssues[0];
  const count = params.blockingIssues.length;
  if (!first) {
    return `ClawScan blocked skill install. Artifact: ${params.artifactPath}`;
  }
  const more = count > 1 ? ` and ${count - 1} more blocking finding${count === 2 ? "" : "s"}` : "";
  return `ClawScan blocked skill install: ${first.scanner} ${first.severity.toUpperCase()} ${first.ruleId} at ${first.file}:${first.line}${more}. Artifact: ${params.artifactPath}`;
}

function summarizeExecutionFailureBlockReason(params: {
  artifactPath: string;
  failures: readonly ClawScanExecutionFailure[];
}): string {
  const first = params.failures[0];
  const count = params.failures.length;
  if (!first) {
    return `ClawScan blocked skill install because scan execution failed. Artifact: ${params.artifactPath}`;
  }
  const more = count > 1 ? ` and ${count - 1} more scan failure${count === 2 ? "" : "s"}` : "";
  return `ClawScan blocked skill install because ${first.label} failed: ${first.message}${more}. Artifact: ${params.artifactPath}`;
}

export function createBeforeInstallResult(params: {
  artifact: unknown;
  artifactPath: string;
  config: ClawScanPluginConfig;
}): BeforeInstallResult | undefined {
  const issues = collectClawScanIssues(params.artifact);
  const executionFailures = collectClawScanExecutionFailures(params.artifact);
  if (issues.length === 0 && executionFailures.length === 0) {
    return undefined;
  }
  const findings = [
    ...issues.map((issue) => ({
      ruleId: issue.ruleId,
      severity: findingSeverity(issue.severity),
      file: issue.file,
      line: issue.line,
      message: `${issue.scanner} ${issue.severity.toUpperCase()}: ${issue.message}`,
    })),
    ...executionFailures.map((failure) => ({
      ruleId: failure.ruleId,
      severity: "critical" as const,
      file: failure.file,
      line: failure.line,
      message: `${failure.label} failed: ${failure.message}`,
    })),
  ].slice(0, MAX_HOOK_FINDINGS);
  const blockSeverity = params.config.beforeInstall?.blockSeverity ?? "high";
  const minimumRank = severityRank(blockSeverity);
  const blockingIssues = issues.filter((issue) => severityRank(issue.severity) >= minimumRank);
  if (executionFailures.length > 0) {
    return {
      findings,
      block: true,
      blockReason: summarizeExecutionFailureBlockReason({
        artifactPath: params.artifactPath,
        failures: executionFailures,
      }),
    };
  }
  if (blockingIssues.length === 0) {
    return { findings };
  }
  return {
    findings,
    block: true,
    blockReason: summarizeBlockReason({
      artifactPath: params.artifactPath,
      blockingIssues,
    }),
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

export async function summarizeClawScanArtifactFile(
  outputPath: string,
): Promise<ScanSummary | undefined> {
  let file;
  try {
    file = await open(outputPath, "r");
    const info = await file.stat();
    if (!info.isFile() || info.size <= 0 || info.size > MAX_ARTIFACT_SUMMARY_BYTES) {
      return undefined;
    }
    const buffer = Buffer.alloc(info.size);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    return summarizeArtifact(JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")));
  } catch {
    return undefined;
  } finally {
    await file?.close();
  }
}

async function readArtifactJson(outputPath: string): Promise<ArtifactReadResult> {
  let file;
  try {
    file = await open(outputPath, "r");
    const info = await file.stat();
    if (!info.isFile()) {
      return { ok: false, reason: "artifact path is not a file" };
    }
    if (info.size <= 0) {
      return { ok: false, reason: "artifact is empty" };
    }
    if (info.size > MAX_ARTIFACT_SUMMARY_BYTES) {
      return { ok: false, reason: `artifact exceeds ${MAX_ARTIFACT_SUMMARY_BYTES} bytes` };
    }
    const buffer = Buffer.alloc(info.size);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    return {
      ok: true,
      artifact: JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: message || "artifact could not be read" };
  } finally {
    await file?.close();
  }
}

async function runBeforeInstallClawScan(
  event: BeforeInstallEvent,
  config: ClawScanPluginConfig,
): Promise<BeforeInstallResult | undefined> {
  const invocation = buildBeforeInstallClawScanInvocation(event, config);
  if (!invocation) {
    return undefined;
  }
  await mkdir(path.dirname(invocation.outputPath), { recursive: true });
  const result = await runCommand(invocation);
  const artifactRead = await readArtifactJson(invocation.outputPath);
  if (!artifactRead.ok) {
    return {
      block: true,
      blockReason: `ClawScan artifact could not be read during before_install: ${artifactRead.reason}. Artifact: ${invocation.outputPath}`,
    };
  }
  const hookResult = createBeforeInstallResult({
    artifact: artifactRead.artifact,
    artifactPath: invocation.outputPath,
    config,
  });
  if (result.exitCode !== 0) {
    return {
      findings: hookResult?.findings,
      block: true,
      blockReason: `ClawScan failed during before_install with exit code ${result.exitCode}. Artifact: ${invocation.outputPath}`,
    };
  }
  if (hookResult) {
    return hookResult;
  }
  return undefined;
}

function registerBeforeInstallHook(api: OpenClawPluginApi, config: ClawScanPluginConfig): void {
  api.on(
    "before_install",
    async (event) => await runBeforeInstallClawScan(event as BeforeInstallEvent, config),
  );
}

const entry = defineToolPlugin({
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
        const summary =
          (await summarizeClawScanArtifactFile(invocation.outputPath)) ?? summarizeClawScanJson(result.stdout);
        return {
          ok: result.exitCode === 0,
          exitCode: result.exitCode,
          artifactPath: invocation.outputPath,
          command: invocation.command,
          args: invocation.args,
          summary,
          stdoutTruncated: result.stdoutTruncated,
          stderrTruncated: result.stderrTruncated,
          stderrPresent: result.stderr.trim().length > 0,
        };
      },
    }),
  ],
});

const registerTools = entry.register;
entry.register = (api: OpenClawPluginApi) => {
  registerTools(api);
  registerBeforeInstallHook(api, (api.pluginConfig ?? {}) as ClawScanPluginConfig);
};

export default entry;
