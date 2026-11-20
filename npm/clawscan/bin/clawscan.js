#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { resolveBundledBinaryPath } from "../lib/resolve-binary.mjs";

let binaryPath;
try {
  binaryPath = resolveBundledBinaryPath();
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
