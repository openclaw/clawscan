import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { binaryFileName, platformKey, resolveBinaryPath } from "../lib/resolve-binary.mjs";

describe("platformKey", () => {
  it("maps supported Node platform and arch pairs to package binary directories", () => {
    assert.equal(platformKey("linux", "x64"), "linux-x64");
    assert.equal(platformKey("linux", "arm64"), "linux-arm64");
    assert.equal(platformKey("darwin", "x64"), "darwin-x64");
    assert.equal(platformKey("darwin", "arm64"), "darwin-arm64");
    assert.equal(platformKey("win32", "x64"), "win32-x64");
  });

  it("rejects unsupported platform and arch pairs with a useful message", () => {
    assert.throws(
      () => platformKey("freebsd", "x64"),
      /Unsupported platform for @openclaw\/clawscan: freebsd-x64/,
    );
  });
});

describe("binaryFileName", () => {
  it("uses the Windows executable suffix only on win32", () => {
    assert.equal(binaryFileName("linux"), "clawscan");
    assert.equal(binaryFileName("darwin"), "clawscan");
    assert.equal(binaryFileName("win32"), "clawscan.exe");
  });
});

describe("resolveBinaryPath", () => {
  it("resolves the bundled binary path relative to the package root", () => {
    assert.match(
      resolveBinaryPath({
        packageRoot: "/tmp/package",
        platform: "darwin",
        arch: "arm64",
      }),
      /\/tmp\/package\/binaries\/darwin-arm64\/clawscan$/,
    );
  });
});
