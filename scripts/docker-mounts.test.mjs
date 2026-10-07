import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const binary = resolve(process.env.CLAWSCAN_BIN || "./clawscan");

for (const name of ["plain", 'My Skill, "v2"']) {
  test(`Docker preserves paths and mount permissions: ${name}`, { timeout: 120_000 }, () => {
    const root = mkdtempSync(join(tmpdir(), "clawscan-docker-mounts-"));
    try {
      const target = join(root, name);
      const rules = join(root, `${name} rules`);
      const cache = join(root, `${name} cache`);
      for (const path of [target, rules, cache]) mkdirSync(path);
      writeFileSync(join(target, "SKILL.md"), "# Synthetic mount fixture\n");
      writeFileSync(join(rules, "rule.txt"), "synthetic rule\n");
      writeFileSync(join(target, "probe.sh"), `set -eu
test "$(cat "$1/SKILL.md")" = "# Synthetic mount fixture"
test "$(cat "$PROOF_RULES/rule.txt")" = "synthetic rule"
if (printf changed > "$1/SKILL.md") 2>/dev/null; then
  echo "target unexpectedly writable" >&2
  exit 1
fi
if (touch "$PROOF_RULES/unexpected") 2>/dev/null; then
  echo "rules unexpectedly writable" >&2
  exit 1
fi
printf 'container wrote cache\n' > "$PROOF_CACHE/proof.txt"
printf '{"targetReadOnly":true,"rulesReadOnly":true,"cacheWritable":true}\n'
`);
      const config = join(root, "config.json");
      writeFileSync(config, JSON.stringify({
        version: 1,
        profiles: {
          proof: {
            scanners: [{
              id: "mount-proof",
              command: "sh {{target}}/probe.sh {{target}}",
              env: ["PROOF_RULES", "PROOF_CACHE"],
              targets: ["skill"],
            }],
            sandbox: {
              image: "alpine:3.23",
              mounts: [rules, { path: cache, write: true }],
            },
          },
        },
      }));
      const stdout = execFileSync(binary, [target, "--config", config, "--profile", "proof", "--sandbox", "docker", "--json"], {
        encoding: "utf8",
        timeout: 110_000,
        env: { ...process.env, PROOF_RULES: rules, PROOF_CACHE: cache },
      });
      const artifact = JSON.parse(stdout);
      const scanner = artifact.scanners["mount-proof"];
      assert.equal(scanner.status, "completed", JSON.stringify(scanner));
      assert.deepEqual(scanner.raw, { targetReadOnly: true, rulesReadOnly: true, cacheWritable: true });
      assert.equal(readFileSync(join(target, "SKILL.md"), "utf8"), "# Synthetic mount fixture\n");
      assert.equal(readFileSync(join(cache, "proof.txt"), "utf8"), "container wrote cache\n");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
