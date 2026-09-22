import assert from "node:assert/strict";
import test from "node:test";
import { releaseNotes } from "./release-notes.mjs";

const metadata = {
  name: "@openclaw/clawscan",
  version: "0.2.0",
  dist: {
    tarball: "https://registry.npmjs.org/@openclaw/clawscan/-/clawscan-0.2.0.tgz",
    integrity: "sha512-dGVzdA==",
  },
};
const changelog = "# Changelog\n\n## Unreleased\n\n## 0.2.0 - 2026-09-22\n\n**Highlights:** Changes.\n\n- Fixed.\n\n## 0.1.8 - 2026-09-10\n\n- Older.\n";

test("publishes only the requested changelog section and verified package metadata", () => {
  const notes = releaseNotes(changelog, "v0.2.0", metadata);
  assert.ok(notes.startsWith("**Highlights:** Changes.\n\n- Fixed.\n\n## Package"));
  assert.ok(!notes.includes("Older") && !notes.includes("Unreleased"));
  assert.ok(notes.includes(metadata.dist.tarball));
  assert.ok(notes.includes(metadata.dist.integrity));
  assert.equal(releaseNotes(changelog.split("## 0.1.8")[0], "v0.2.0", metadata), notes);
});

test("refuses missing or empty notes and mismatched registry metadata", () => {
  assert.throws(() => releaseNotes("## Unreleased", "v0.2.0", metadata), /Missing/);
  assert.throws(() => releaseNotes("## 0.2.0 - 2026-09-22\n", "v0.2.0", metadata), /Empty/);
  assert.throws(() => releaseNotes(changelog, "v0.2.0", { ...metadata, version: "0.1.8" }), /match/);
  assert.throws(() => releaseNotes(changelog, "v0.2.0", { ...metadata, dist: {} }), /tarball/);
});
