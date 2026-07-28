import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

describe("@openclaw/clawscan-plugin package", () => {
  it("declares the install gate manifest and an exact matching binary dependency", async () => {
    const packageJson = await readJson(join(packageRoot, "package.json"));
    const manifest = await readJson(join(packageRoot, "openclaw.plugin.json"));

    assert.equal(packageJson.name, "@openclaw/clawscan-plugin");
    assert.equal(packageJson.version, "0.0.0-dev");
    assert.equal(packageJson.dependencies["@openclaw/clawscan"], packageJson.version);
    assert.equal(packageJson.peerDependencies.openclaw, ">=2026.7.2");
    assert.equal(packageJson.peerDependenciesMeta.openclaw.optional, true);
    assert.deepEqual(packageJson.openclaw.extensions, ["./index.ts"]);
    assert.equal(packageJson.openclaw.install.npmSpec, "@openclaw/clawscan-plugin");
    assert.equal(manifest.id, "clawscan");
    assert.equal(manifest.activation.onStartup, false);
    assert.deepEqual(manifest.activation.onCapabilities, ["hook"]);
    assert.equal(manifest.enabledByDefault, undefined);
  });

  it("packs the manifest and profile without tests or install-time lifecycle bypasses", async () => {
    const packageJson = await readJson(join(packageRoot, "package.json"));
    const packed = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: packageRoot,
      encoding: "utf8",
    });
    assert.equal(packed.status, 0, packed.stderr);
    const report = JSON.parse(packed.stdout)[0];
    const files = report.files.map((entry) => entry.path).sort();

    assert.ok(files.includes("openclaw.plugin.json"));
    assert.ok(files.includes("profiles/clawhub.yml"));
    assert.ok(files.includes("index.ts"));
    assert.ok(files.includes("src/gate-handler.ts"));
    assert.equal(
      files.some((path) => path.startsWith("test/")),
      false,
    );
    assert.equal(packageJson.scripts?.preinstall, undefined);
    assert.equal(packageJson.scripts?.install, undefined);
    assert.equal(packageJson.scripts?.postinstall, undefined);
  });

  it("keeps the entrypoint free of direct process-spawning imports", async () => {
    const entrypoint = await readFile(join(packageRoot, "index.ts"), "utf8");
    const register = await readFile(join(packageRoot, "src", "register.ts"), "utf8");
    const handler = await readFile(join(packageRoot, "src", "gate-handler.ts"), "utf8");
    const forbiddenModule = ["node:child", "process"].join("_");

    assert.doesNotMatch(entrypoint, new RegExp(forbiddenModule));
    assert.doesNotMatch(register, new RegExp(forbiddenModule));
    assert.doesNotMatch(handler, new RegExp(forbiddenModule));
  });

  it("ships a no-judge profile with both required native gate scanners", async () => {
    const profile = await readFile(join(packageRoot, "profiles", "clawhub.yml"), "utf8");

    assert.match(profile, /id: skillspector/);
    assert.match(profile, /id: clawscan-static/);
    assert.match(profile, /native: true/);
    assert.doesNotMatch(profile, /\bjudge:/);
  });
});
