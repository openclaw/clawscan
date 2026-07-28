import process from "node:process";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { gateResultFromArtifact, type BeforeInstallResult } from "./artifact.ts";

const DOCKER_PROBE_TIMEOUT_MS = 5_000;
const SCAN_TIMEOUT_MS = 600_000;
const MAX_STDOUT_BYTES = 8 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

type HostRunCommand = OpenClawPluginApi["runtime"]["system"]["runCommandWithTimeout"];

export type CommandOptions = Exclude<Parameters<HostRunCommand>[1], number>;
export type CommandResult = Awaited<ReturnType<HostRunCommand>>;

export type GateHandlerDependencies = {
  platform?: NodeJS.Platform;
  runCommand: (argv: string[], options: CommandOptions) => Promise<CommandResult>;
  resolveBinaryPath: () => string;
  resolveConfigPath: () => string;
  resolveFallbackConfigPath?: () => string;
  profile: string;
  requiredScanners?: readonly string[];
};

export type BeforeInstallEvent = {
  sourcePath: string;
};

function commandSucceeded(result: CommandResult): boolean {
  return (
    result.code === 0 &&
    result.signal === null &&
    result.termination === "exit" &&
    result.outputLimitExceeded !== true
  );
}

function cleanDiagnostic(message: string, limit = 600): string {
  return message
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, limit);
}

function failClosed(message: string): BeforeInstallResult {
  const cleaned = cleanDiagnostic(message);
  const reason = cleaned || "ClawScan could not complete the install-time scan";
  return {
    block: true,
    blockReason: `ClawScan blocked installation: ${reason}`,
    findings: [
      {
        ruleId: "clawscan/gate-failure",
        severity: "critical",
        file: ".",
        line: 1,
        message: reason,
      },
    ],
  };
}

function commandFailure(label: string, result: CommandResult): BeforeInstallResult {
  if (result.outputLimitExceeded === true) {
    return failClosed(`${label} exceeded its output limit`);
  }
  if (result.termination === "timeout" || result.termination === "no-output-timeout") {
    return failClosed(`${label} timed out`);
  }
  if (result.signal !== null || result.termination === "signal") {
    const signal = cleanDiagnostic(result.signal ?? "unknown signal", 40);
    return failClosed(`${label} was terminated by ${signal}`);
  }
  if (typeof result.code === "number") {
    const stderr = cleanDiagnostic(result.stderr, 480);
    return failClosed(`${label} exited with code ${result.code}${stderr ? `: ${stderr}` : ""}`);
  }
  return failClosed(`${label} failed without an exit code`);
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

const degradedFinding = {
  ruleId: "clawscan/docker-unavailable",
  severity: "warn" as const,
  file: ".",
  line: 1,
  message: "Gate degraded: Docker mode unavailable on this host; clawscan-static only.",
};

const scanCommandOptions: CommandOptions = {
  timeoutMs: SCAN_TIMEOUT_MS,
  env: { CLAWSCAN_SKILLSPECTOR_LLM: "0" },
  maxOutputBytes: {
    stdout: MAX_STDOUT_BYTES,
    stderr: MAX_STDERR_BYTES,
  },
  outputCapture: "head",
  terminateOnOutputLimit: true,
};

export function createBeforeInstallHandler(dependencies: GateHandlerDependencies) {
  return async (event: BeforeInstallEvent): Promise<BeforeInstallResult | undefined> => {
    try {
      let dockerAvailable = false;
      if ((dependencies.platform ?? process.platform) !== "win32") {
        try {
          const dockerProbe = await dependencies.runCommand(["docker", "info"], {
            timeoutMs: DOCKER_PROBE_TIMEOUT_MS,
          });
          dockerAvailable = commandSucceeded(dockerProbe);
        } catch {
          dockerAvailable = false;
        }
      }
      const binaryPath = dependencies.resolveBinaryPath();
      if (!dockerAvailable) {
        const fallbackConfigPath =
          dependencies.resolveFallbackConfigPath?.() ?? dependencies.resolveConfigPath();
        const scan = await dependencies.runCommand(
          [
            binaryPath,
            event.sourcePath,
            "--config",
            fallbackConfigPath,
            "--profile",
            "clawhub-static",
            "--scanner",
            "clawscan-static",
            "--sandbox",
            "off",
            "--json",
          ],
          scanCommandOptions,
        );
        if (!commandSucceeded(scan)) {
          const failure = commandFailure("ClawScan static fallback", scan);
          return {
            ...failure,
            findings: [degradedFinding, ...(failure.findings ?? [])],
          };
        }
        const result = gateResultFromArtifact(scan.stdout, ["clawscan-static"]);
        return {
          ...result,
          findings: [degradedFinding, ...(result?.findings ?? [])],
        };
      }

      const configPath = dependencies.resolveConfigPath();
      const scan = await dependencies.runCommand(
        [
          binaryPath,
          event.sourcePath,
          "--config",
          configPath,
          "--profile",
          dependencies.profile,
          "--sandbox",
          "docker",
          "--json",
        ],
        scanCommandOptions,
      );
      if (!commandSucceeded(scan)) {
        return commandFailure("ClawScan process", scan);
      }
      return gateResultFromArtifact(scan.stdout, dependencies.requiredScanners ?? []);
    } catch (error) {
      if (errorCode(error) === "ENOENT") {
        return failClosed("ClawScan binary was not found");
      }
      return failClosed("ClawScan could not start the install-time scan");
    }
  };
}
