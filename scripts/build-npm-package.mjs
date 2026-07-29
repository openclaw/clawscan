#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
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
  { goos: "windows", goarch: "arm64" },
];

export function normalizePackageVersion(version) {
  const match = String(version ?? "")
    .trim()
    .match(semverPattern);
  if (!match) {
    throw new Error("Expected a semver npm package version or v-prefixed semver tag.");
  }
  return match[1];
}

export function normalizeBuildDate(value) {
  const parsed = new Date(String(value ?? "").trim());
  if (Number.isNaN(parsed.valueOf())) {
    throw new Error("Expected a valid commit timestamp for the package build date.");
  }
  return parsed.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function binaryVersionFor(version) {
  const trimmed = String(version ?? "").trim();
  const packageVersion = normalizePackageVersion(trimmed);
  return trimmed.startsWith("v") ? trimmed : `v${packageVersion}`;
}

export function npmDistTagForVersion(version) {
  return normalizePackageVersion(version).includes("-") ? "next" : "latest";
}

export function platformKeyForTarget(target) {
  const arch = target.goarch === "amd64" ? "x64" : target.goarch;
  const platform = target.goos === "windows" ? "win32" : target.goos;
  return `${platform}-${arch}`;
}

export function binaryNameForTarget(target) {
  return target.goos === "windows" ? "clawscan.exe" : "clawscan";
}

export function preparePluginPackageJson(packageJson, packageVersion) {
  return {
    ...packageJson,
    version: packageVersion,
    files: [...new Set([...(packageJson.files ?? []), "dist/"])],
    dependencies: {
      ...packageJson.dependencies,
      "@openclaw/clawscan": packageVersion,
    },
    openclaw: {
      ...packageJson.openclaw,
      runtimeExtensions: ["./dist/index.js"],
    },
  };
}

const pluginRuntimeSources = [
  "index.ts",
  join("src", "artifact.ts"),
  join("src", "gate-handler.ts"),
  join("src", "register.ts"),
];

export function compilePluginTypeScript(source) {
  return stripTypeScriptTypes(source, { mode: "transform" }).replace(
    /((?:from\s+|import\s*)["'](?:\.\.?\/)[^"']+)\.ts(["'])/gu,
    "$1.js$2",
  );
}

async function stagePluginRuntime(pluginPackageSource, pluginPackageOut) {
  for (const relativeSource of pluginRuntimeSources) {
    const destination = join(pluginPackageOut, "dist", relativeSource.replace(/\.ts$/u, ".js"));
    await mkdir(dirname(destination), { recursive: true });
    const source = await readFile(join(pluginPackageSource, relativeSource), "utf8");
    await writeFile(destination, compilePluginTypeScript(source));
  }
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
    throw new Error(
      `${command} ${args.join(" ")} failed with exit ${result.status}${stderr}${stdout}`,
    );
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

async function stagePackages(options) {
  const packageVersion = normalizePackageVersion(options.version);
  const binaryVersion = binaryVersionFor(options.version);
  const releaseSha = run("git", ["rev-parse", "HEAD"]).stdout.trim();
  const releaseCommit = run("git", ["rev-parse", "--short", "HEAD"]).stdout.trim();
  const buildDate = normalizeBuildDate(
    run("git", ["show", "-s", "--format=%cI", "HEAD"]).stdout.trim(),
  );
  const packageSource = join(repoRoot, "npm", "clawscan");
  const pluginPackageSource = join(repoRoot, "npm", "clawscan-plugin");
  const packageOut = join(options.outDir, "package");
  const pluginPackageOut = join(options.outDir, "clawscan-plugin-package");

  await rm(options.outDir, { recursive: true, force: true });
  await mkdir(packageOut, { recursive: true });
  await mkdir(pluginPackageOut, { recursive: true });
  await cp(packageSource, packageOut, {
    recursive: true,
    filter: (source) => !source.includes(`${join("npm", "clawscan", "test")}`),
  });
  await rm(join(packageOut, "test"), { recursive: true, force: true });
  await rm(join(packageOut, "binaries"), { recursive: true, force: true });
  await cp(join(repoRoot, "README.md"), join(packageOut, "README.md"));
  await cp(join(repoRoot, "LICENSE"), join(packageOut, "LICENSE"));
  await chmod(join(packageOut, "bin", "clawscan.js"), 0o755);
  await cp(pluginPackageSource, pluginPackageOut, {
    recursive: true,
    filter: (source) => !source.includes(`${join("npm", "clawscan-plugin", "test")}`),
  });
  await rm(join(pluginPackageOut, "test"), { recursive: true, force: true });
  await cp(join(repoRoot, "LICENSE"), join(pluginPackageOut, "LICENSE"));
  await stagePluginRuntime(pluginPackageSource, pluginPackageOut);

  const packageJsonPath = join(packageOut, "package.json");
  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
  packageJson.version = packageVersion;
  await writeFile(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
  const pluginPackageJsonPath = join(pluginPackageOut, "package.json");
  const pluginPackageJson = preparePluginPackageJson(
    JSON.parse(await readFile(pluginPackageJsonPath, "utf8")),
    packageVersion,
  );
  await writeFile(pluginPackageJsonPath, `${JSON.stringify(pluginPackageJson, null, 2)}\n`);

  const ldflags = `-s -w -X main.version=${binaryVersion} -X main.commit=${releaseCommit} -X main.date=${buildDate}`;
  for (const target of packageTargets) {
    const binaryDir = join(packageOut, "binaries", platformKeyForTarget(target));
    await mkdir(binaryDir, { recursive: true });
    run(
      "go",
      [
        "build",
        "-trimpath",
        "-ldflags",
        ldflags,
        "-o",
        join(binaryDir, binaryNameForTarget(target)),
        "github.com/openclaw/clawscan/cmd/clawscan",
      ],
      {
        env: {
          ...process.env,
          GOOS: target.goos,
          GOARCH: target.goarch,
          CGO_ENABLED: "0",
        },
      },
    );
  }

  await writeFile(join(options.outDir, "release-tag.txt"), `${binaryVersion}\n`);
  await writeFile(join(options.outDir, "release-sha.txt"), `${releaseSha}\n`);
  await writeFile(join(options.outDir, "package-version.txt"), `${packageVersion}\n`);

  return { binaryVersion, packageOut, packageVersion, pluginPackageOut, releaseSha };
}

async function packPackage(options, packageOut) {
  const result = run(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", options.outDir],
    {
      cwd: packageOut,
    },
  );
  const parsed = JSON.parse(result.stdout);
  const first = Array.isArray(parsed) ? parsed[0] : undefined;
  if (!first?.filename) throw new Error("npm pack did not return a tarball filename.");
  return resolve(options.outDir, first.filename);
}

async function smokePackages(
  clawscanTarballPath,
  pluginTarballPath,
  binaryVersion,
  packageVersion,
) {
  const prefix = await mkdtemp(join(tmpdir(), "clawscan-npm-smoke-"));
  const pluginPrefix = await mkdtemp(join(tmpdir(), "clawscan-plugin-npm-smoke-"));
  try {
    run("npm", ["install", "-g", "--prefix", prefix, clawscanTarballPath]);
    const binPath =
      process.platform === "win32" ? join(prefix, "clawscan.cmd") : join(prefix, "bin", "clawscan");
    const version = run(binPath, ["--version"]).stdout.trim();
    if (!version.includes(`clawscan ${binaryVersion} `)) {
      throw new Error(`Unexpected clawscan --version output: ${version}`);
    }
    const smoke = run(binPath, [
      join(repoRoot, "README.md"),
      "--scanner",
      "clawscan-static",
      "--json",
    ]);
    JSON.parse(smoke.stdout);

    run("npm", ["install", "--prefix", pluginPrefix, clawscanTarballPath]);
    run("npm", ["install", "--prefix", pluginPrefix, pluginTarballPath]);
    const installedPluginRoot = join(pluginPrefix, "node_modules", "@openclaw", "clawscan-plugin");
    const installedPackageJson = JSON.parse(
      await readFile(join(installedPluginRoot, "package.json"), "utf8"),
    );
    if (
      installedPackageJson.version !== packageVersion ||
      installedPackageJson.dependencies?.["@openclaw/clawscan"] !== packageVersion ||
      installedPackageJson.peerDependencies?.openclaw !== ">=2026.7.2" ||
      installedPackageJson.openclaw?.install?.minHostVersion !== ">=2026.7.2" ||
      installedPackageJson.openclaw?.compat?.pluginApi !== ">=2026.7.2"
    ) {
      throw new Error("Installed ClawScan plugin did not preserve its host and binary contracts.");
    }
    await readFile(join(installedPluginRoot, "openclaw.plugin.json"), "utf8");
    await readFile(join(installedPluginRoot, "profiles", "clawhub.yml"), "utf8");
    await readFile(join(installedPluginRoot, "dist", "index.js"), "utf8");

    const hostPackageRoot = join(pluginPrefix, "node_modules", "openclaw");
    await mkdir(join(hostPackageRoot, "plugin-sdk"), { recursive: true });
    await writeFile(
      join(hostPackageRoot, "package.json"),
      `${JSON.stringify(
        {
          name: "openclaw",
          version: "2026.7.2",
          type: "module",
          exports: {
            "./plugin-sdk/plugin-entry": "./plugin-sdk/plugin-entry.mjs",
          },
        },
        null,
        2,
      )}\n`,
    );
    await writeFile(
      join(hostPackageRoot, "plugin-sdk", "plugin-entry.mjs"),
      "export const definePluginEntry = (definition) => definition;\n",
    );
    const entrypointSmokeRoot = join(pluginPrefix, "packed-entrypoint-smoke");
    await cp(installedPluginRoot, entrypointSmokeRoot, { recursive: true });
    const runtimeEntry = installedPackageJson.openclaw?.runtimeExtensions?.[0];
    if (runtimeEntry !== "./dist/index.js") {
      throw new Error("Installed ClawScan plugin did not declare its built runtime entrypoint.");
    }
    const entrypointUrl = pathToFileURL(join(entrypointSmokeRoot, runtimeEntry)).href;
    run(
      "node",
      [
        "--input-type=module",
        "--eval",
        `const plugin = (await import(${JSON.stringify(entrypointUrl)})).default; if (plugin?.id !== "clawscan" || typeof plugin?.register !== "function") throw new Error("packed plugin entrypoint did not load");`,
      ],
      { cwd: pluginPrefix },
    );
  } finally {
    await rm(prefix, { recursive: true, force: true });
    await rm(pluginPrefix, { recursive: true, force: true });
  }
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const staged = await stagePackages(options);
  let clawscanTarballPath = "";
  let pluginTarballPath = "";
  if (options.pack) {
    clawscanTarballPath = await packPackage(options, staged.packageOut);
    pluginTarballPath = await packPackage(options, staged.pluginPackageOut);
  }
  if (options.smoke) {
    await smokePackages(
      clawscanTarballPath,
      pluginTarballPath,
      staged.binaryVersion,
      staged.packageVersion,
    );
  }
  console.log(`clawscan npm package staged: ${staged.packageOut}`);
  console.log(`clawscan plugin npm package staged: ${staged.pluginPackageOut}`);
  console.log(`package version: ${staged.packageVersion}`);
  console.log(`binary version: ${staged.binaryVersion}`);
  if (clawscanTarballPath) console.log(`clawscan npm tarball: ${clawscanTarballPath}`);
  if (pluginTarballPath) console.log(`clawscan plugin npm tarball: ${pluginTarballPath}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
