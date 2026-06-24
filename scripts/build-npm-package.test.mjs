import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binaryNameForTarget,
  normalizePackageVersion,
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
