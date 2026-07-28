import {
  createBeforeInstallHandler,
  type BeforeInstallEvent,
  type CommandOptions,
  type CommandResult,
} from "./gate-handler.ts";
import type { BeforeInstallResult } from "./artifact.ts";

const DEFAULT_CONFIG_PATH = "profiles/clawhub.yml";
const DEFAULT_PROFILE = "clawhub";
const HOOK_TIMEOUT_MS = 615_000;

export type RegisteredHandler = (
  event: BeforeInstallEvent,
) => Promise<BeforeInstallResult | undefined>;

export type GatePluginApi = {
  pluginConfig?: Record<string, unknown>;
  resolvePath: (input: string) => string;
  runtime: {
    system: {
      runCommandWithTimeout: (argv: string[], options: CommandOptions) => Promise<CommandResult>;
    };
  };
  on: (
    name: "before_install",
    handler: RegisteredHandler,
    options: { priority: number; timeoutMs: number },
  ) => void;
};

function configuredString(
  pluginConfig: Record<string, unknown> | undefined,
  key: string,
  fallback: string,
): string {
  const value = pluginConfig?.[key];
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function requiredScannersForShippedConfig(configPath: string, profile: string): readonly string[] {
  if (configPath !== DEFAULT_CONFIG_PATH) {
    return [];
  }
  if (profile === "clawhub") {
    return ["skillspector", "clawscan-static"];
  }
  if (profile === "clawhub-static") {
    return ["clawscan-static"];
  }
  return [];
}

export function registerInstallGate(api: GatePluginApi, resolveBinaryPath: () => string): void {
  const configPath = configuredString(api.pluginConfig, "configPath", DEFAULT_CONFIG_PATH);
  const profile = configuredString(api.pluginConfig, "profile", DEFAULT_PROFILE);
  const handler = createBeforeInstallHandler({
    resolveBinaryPath,
    resolveConfigPath: () => api.resolvePath(configPath),
    resolveFallbackConfigPath: () => api.resolvePath(DEFAULT_CONFIG_PATH),
    profile,
    requiredScanners: requiredScannersForShippedConfig(configPath, profile),
    runCommand: async (argv, options) =>
      await api.runtime.system.runCommandWithTimeout(argv, options),
  });

  api.on("before_install", handler, {
    priority: 100,
    timeoutMs: HOOK_TIMEOUT_MS,
  });
}
