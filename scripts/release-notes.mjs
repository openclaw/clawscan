import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { normalizePackageVersion } from "./build-npm-package.mjs";

export function releaseNotes(changelog, tag, metadata) {
  const version = normalizePackageVersion(tag);
  const lines = changelog.split("\n");
  const start = lines.findIndex((line) => line.startsWith(`## ${version} - `));
  if (start === -1) throw new Error(`Missing changelog section for ${version}`);
  const end = lines.findIndex((line, index) => index > start && line.startsWith("## "));
  const body = lines.slice(start + 1, end === -1 ? undefined : end).join("\n").trim();
  if (!body) throw new Error(`Empty changelog section for ${version}`);
  if (metadata.name !== "@openclaw/clawscan" || metadata.version !== version) {
    throw new Error("npm metadata does not match the release");
  }
  const tarball = metadata.dist?.tarball;
  const integrity = metadata.dist?.integrity;
  if (tarball !== `https://registry.npmjs.org/@openclaw/clawscan/-/clawscan-${version}.tgz` ||
      !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity ?? "")) {
    throw new Error("npm metadata is missing a valid registry tarball or integrity");
  }
  return `${body}\n\n## Package\n\n` +
    `[npm ${version}](https://www.npmjs.com/package/@openclaw/clawscan/v/${version}) · ` +
    `[Registry tarball](${tarball})\n\nIntegrity: \`${integrity}\`\n`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(releaseNotes(
    readFileSync("CHANGELOG.md", "utf8"),
    process.argv[2],
    JSON.parse(readFileSync(process.argv[3], "utf8")),
  ));
}
