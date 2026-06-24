#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = dirname(dirname(scriptPath));
const semverPattern =
  /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$/;

export const packageTargets = [
  { goos: "darwin", goarch: "amd64" },
  { goos: "darwin", goarch: "arm64" },
  { goos: "linux", goarch: "amd64" },
  { goos: "linux", goarch: "arm64" },
  { goos: "windows", goarch: "amd64" },
];

export function normalizePackageVersion(version) {
  const match = String(version ?? "").trim().match(semverPattern);
  if (!match) {
    throw new Error("Expected a semver npm package version or v-prefixed semver tag.");
  }
  return match[1];
}

export function binaryVersionFor(version) {
  const trimmed = String(version ?? "").trim();
  const packageVersion = normalizePackageVersion(trimmed);
  return trimmed.startsWith("v") ? trimmed : `v${packageVersion}`;
}

export function platformKeyForTarget(target) {
  const arch = target.goarch === "amd64" ? "x64" : target.goarch;
  const platform = target.goos === "windows" ? "win32" : target.goos;
  return `${platform}-${arch}`;
}

export function binaryNameForTarget(target) {
  return target.goos === "windows" ? "clawscan.exe" : "clawscan";
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? process.env,
    encoding: "utf8",
    stdio: options.stdio ?? "pipe",
  });
  if (result.status !== 0) {
    const stderr = result.stderr ? `\n${result.stderr.trim()}` : "";
    const stdout = result.stdout ? `\n${result.stdout.trim()}` : "";
    throw new Error(`${command} ${args.join(" ")} failed with exit ${result.status}${stderr}${stdout}`);
  }
  return result;
}

function parseArgs(argv) {
  const options = {
    outDir: join(repoRoot, "dist", "npm"),
    pack: false,
    smoke: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--version") {
      options.version = argv[++index];
      continue;
    }
    if (arg === "--out") {
      options.outDir = resolve(argv[++index]);
      continue;
    }
    if (arg === "--pack") {
      options.pack = true;
      continue;
    }
    if (arg === "--smoke") {
      options.smoke = true;
      options.pack = true;
      continue;
    }
    throw new Error(`Unknown option: ${arg}`);
  }
  if (!options.version) throw new Error("Missing required --version <semver-or-vtag>.");
  return options;
}

async function stagePackage(options) {
  const packageVersion = normalizePackageVersion(options.version);
  const binaryVersion = binaryVersionFor(options.version);
  const releaseSha = run("git", ["rev-parse", "HEAD"]).stdout.trim();
  const releaseCommit = run("git", ["rev-parse", "--short", "HEAD"]).stdout.trim();
  const buildDate = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const packageSource = join(repoRoot, "npm", "clawscan");
  const packageOut = join(options.outDir, "package");

  await rm(options.outDir, { recursive: true, force: true });
  await mkdir(packageOut, { recursive: true });
  await cp(packageSource, packageOut, {
    recursive: true,
    filter: (source) => !source.includes(`${join("npm", "clawscan", "test")}`),
  });
  await rm(join(packageOut, "test"), { recursive: true, force: true });
  await rm(join(packageOut, "binaries"), { recursive: true, force: true });
  await cp(join(repoRoot, "README.md"), join(packageOut, "README.md"));
  await cp(join(repoRoot, "LICENSE"), join(packageOut, "LICENSE"));
  await chmod(join(packageOut, "bin", "clawscan.js"), 0o755);

  const packageJsonPath = join(packageOut, "package.json");
  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
  packageJson.version = packageVersion;
  await writeFile(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);

  const ldflags = `-s -w -X main.version=${binaryVersion} -X main.commit=${releaseCommit} -X main.date=${buildDate}`;
  for (const target of packageTargets) {
    const binaryDir = join(packageOut, "binaries", platformKeyForTarget(target));
    await mkdir(binaryDir, { recursive: true });
    run("go", [
      "build",
      "-trimpath",
      "-ldflags",
      ldflags,
      "-o",
      join(binaryDir, binaryNameForTarget(target)),
      "github.com/openclaw/clawscan/cmd/clawscan",
    ], {
      env: {
        ...process.env,
        GOOS: target.goos,
        GOARCH: target.goarch,
        CGO_ENABLED: "0",
      },
    });
  }

  await writeFile(join(options.outDir, "release-tag.txt"), `${binaryVersion}\n`);
  await writeFile(join(options.outDir, "release-sha.txt"), `${releaseSha}\n`);
  await writeFile(join(options.outDir, "package-version.txt"), `${packageVersion}\n`);

  return { binaryVersion, packageOut, packageVersion, releaseSha };
}

async function packPackage(options, packageOut) {
  const result = run("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", options.outDir], {
    cwd: packageOut,
  });
  const parsed = JSON.parse(result.stdout);
  const first = Array.isArray(parsed) ? parsed[0] : undefined;
  if (!first?.filename) throw new Error("npm pack did not return a tarball filename.");
  return resolve(options.outDir, first.filename);
}

async function smokePackage(tarballPath, binaryVersion) {
  const prefix = await mkdtemp(join(tmpdir(), "clawscan-npm-smoke-"));
  run("npm", ["install", "-g", "--prefix", prefix, tarballPath]);
  const binPath = process.platform === "win32"
    ? join(prefix, "clawscan.cmd")
    : join(prefix, "bin", "clawscan");
  const version = run(binPath, ["--version"]).stdout.trim();
  if (!version.includes(`clawscan ${binaryVersion} `)) {
    throw new Error(`Unexpected clawscan --version output: ${version}`);
  }
  const smoke = run(binPath, [join(repoRoot, "README.md"), "--scanner", "clawscan-static", "--json"]);
  JSON.parse(smoke.stdout);
  await rm(prefix, { recursive: true, force: true });
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const staged = await stagePackage(options);
  let tarballPath = "";
  if (options.pack) {
    tarballPath = await packPackage(options, staged.packageOut);
  }
  if (options.smoke) {
    await smokePackage(tarballPath, staged.binaryVersion);
  }
  console.log(`npm package staged: ${staged.packageOut}`);
  console.log(`package version: ${staged.packageVersion}`);
  console.log(`binary version: ${staged.binaryVersion}`);
  if (tarballPath) console.log(`npm tarball: ${tarballPath}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
