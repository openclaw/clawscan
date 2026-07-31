import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  binaryNameForTarget,
  normalizeBuildDate,
  normalizePackageVersion,
  npmDistTagForVersion,
  packageTargets,
  platformKeyForTarget,
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
    assert.equal(npmDistTagForVersion("v1.2.3+build-7"), "latest");
    assert.equal(npmDistTagForVersion("1.2.3-beta.1"), "next");
    assert.equal(npmDistTagForVersion("1.2.3-beta.1+build-7"), "next");
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
        ["windows", "arm64", "win32-arm64"],
      ],
    );
  });

  it("uses clawscan.exe only for the Windows target", () => {
    assert.equal(binaryNameForTarget({ goos: "linux", goarch: "amd64" }), "clawscan");
    assert.equal(binaryNameForTarget({ goos: "windows", goarch: "amd64" }), "clawscan.exe");
  });
});

describe("GitHub release target mapping", () => {
  it("builds the complete supported archive matrix", () => {
    const releaseScript = readFileSync(new URL("./build-release.sh", import.meta.url), "utf8");
    const matrix = releaseScript.match(/platforms=\(\n(?<entries>(?:\s+"[^"]+"\n)+)\)/u);

    assert.ok(matrix?.groups?.entries, "release platform matrix was not found");
    assert.deepEqual(
      [...matrix.groups.entries.matchAll(/"([^"]+)"/gu)].map((match) => match[1]),
      [
        "darwin/amd64",
        "darwin/arm64",
        "linux/amd64",
        "linux/arm64",
        "windows/amd64",
        "windows/arm64",
      ],
    );
  });
});

describe("npm promotion verification", () => {
  it("checks the expected dist-tag even when publication is skipped", () => {
    const workflow = readFileSync(
      new URL("../.github/workflows/npm-release.yml", import.meta.url),
      "utf8",
    );

    assert.match(workflow, /@openclaw\/clawscan@\$\{NPM_DIST_TAG\}/u);
    assert.match(workflow, /Prerelease \$\{PACKAGE_VERSION\} must not be assigned to the latest/u);
  });
});
