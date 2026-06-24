#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveBinaryPath } from "../lib/resolve-binary.mjs";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

let binaryPath;
try {
  binaryPath = resolveBinaryPath({ packageRoot });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
});

if (result.error) {
  console.error(`Failed to run bundled clawscan binary at ${binaryPath}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  console.error(`Bundled clawscan binary exited from signal ${result.signal}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
