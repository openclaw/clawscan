import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binaryNameForTarget,
  compilePluginTypeScript,
  normalizePackageVersion,
  normalizeBuildDate,
  npmDistTagForVersion,
  packageTargets,
  platformKeyForTarget,
  preparePluginPackageJson,
} from "./build-npm-package.mjs";

describe("normalizePackageVersion", () => {
  it("strips a release tag v-prefix for npm package metadata", () => {
    assert.equal(normalizePackageVersion("v1.2.3"), "1.2.3");
    assert.equal(normalizePackageVersion("v1.2.3-beta.1"), "1.2.3-beta.1");
  });

  it("accepts an already-normalized semver version", () => {
    assert.equal(normalizePackageVersion("1.2.3"), "1.2.3");
  });

  it("rejects non-semver release identifiers", () => {
    assert.throws(
      () => normalizePackageVersion("manual-42"),
      /Expected a semver npm package version or v-prefixed semver tag/,
    );
  });
});

describe("npmDistTagForVersion", () => {
  it("keeps stable releases on latest and prereleases on next", () => {
    assert.equal(npmDistTagForVersion("v1.2.3"), "latest");
    assert.equal(npmDistTagForVersion("1.2.3-beta.1"), "next");
  });
});

describe("normalizeBuildDate", () => {
  it("derives a stable UTC build date from commit metadata", () => {
    assert.equal(normalizeBuildDate("2026-07-28T12:34:56+10:00"), "2026-07-28T02:34:56Z");
  });

  it("rejects invalid commit timestamps", () => {
    assert.throws(() => normalizeBuildDate("not-a-date"), /valid commit timestamp/);
  });
});

describe("package target mapping", () => {
  it("maps Go release targets to npm binary directories", () => {
    assert.deepEqual(
      packageTargets.map((target) => [target.goos, target.goarch, platformKeyForTarget(target)]),
      [
        ["darwin", "amd64", "darwin-x64"],
        ["darwin", "arm64", "darwin-arm64"],
        ["linux", "amd64", "linux-x64"],
        ["linux", "arm64", "linux-arm64"],
        ["windows", "amd64", "win32-x64"],
      ],
    );
  });

  it("uses clawscan.exe only for the Windows target", () => {
    assert.equal(binaryNameForTarget({ goos: "linux", goarch: "amd64" }), "clawscan");
    assert.equal(binaryNameForTarget({ goos: "windows", goarch: "amd64" }), "clawscan.exe");
  });
});

describe("preparePluginPackageJson", () => {
  it("pins the plugin and its binary dependency to the exact release version", () => {
    assert.deepEqual(
      preparePluginPackageJson(
        {
          name: "@openclaw/clawscan-plugin",
          version: "0.0.0-dev",
          dependencies: { "@openclaw/clawscan": "0.0.0-dev" },
        },
        "1.2.3",
      ),
      {
        name: "@openclaw/clawscan-plugin",
        version: "1.2.3",
        files: ["dist/"],
        dependencies: { "@openclaw/clawscan": "1.2.3" },
        openclaw: {
          runtimeExtensions: ["./dist/index.js"],
        },
      },
    );
  });
});

describe("compilePluginTypeScript", () => {
  it("removes types and rewrites local TypeScript imports for the installed runtime", () => {
    const compiled = compilePluginTypeScript(
      'import type { Host } from "openclaw/plugin-sdk/plugin-entry";\n' +
        'import { register } from "./src/register.ts";\n' +
        "const api: Host = register;\n",
    );

    assert.doesNotMatch(compiled, /import type/);
    assert.match(compiled, /from "\.\/src\/register\.js"/);
    assert.doesNotMatch(compiled, /: Host/);
  });
});
