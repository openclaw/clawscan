import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const supportedPlatforms = new Set([
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64",
  "linux-x64",
  "win32-x64",
]);

export function platformKey(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  if (!supportedPlatforms.has(key)) {
    throw new Error(`Unsupported platform for @openclaw/clawscan: ${key}`);
  }
  return key;
}

export function binaryFileName(platform = process.platform) {
  return platform === "win32" ? "clawscan.exe" : "clawscan";
}

export function resolveBinaryPath({
  packageRoot,
  platform = process.platform,
  arch = process.arch,
}) {
  return join(packageRoot, "binaries", platformKey(platform, arch), binaryFileName(platform));
}

export function resolveBundledBinaryPath({
  platform = process.platform,
  arch = process.arch,
} = {}) {
  return resolveBinaryPath({ packageRoot, platform, arch });
}
