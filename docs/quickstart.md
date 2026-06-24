# Quickstart

## Install

Homebrew is the recommended install path on macOS and Linux:

```bash
brew install openclaw/tap/clawscan
```

You can also download a release archive from GitHub Releases. Pick the archive
for your OS and CPU, unpack it, and put the `clawscan` binary on your `PATH`.

If you have Go installed, install from the published module:

```bash
go install github.com/openclaw/clawscan/cmd/clawscan@latest
```

For source builds from a repository checkout:

```bash
make release VERSION=dev
```

Or install a development build directly:

```bash
go install ./cmd/clawscan
```

During development, run the CLI directly:

```bash
go run ./cmd/clawscan ./my-skill --scanner clawscan-static --json
```

## Explicit Scan Selection

From a repository root that stores skills under `./skills/<name>/SKILL.md`,
choose a scanner, profile, config, or benchmark explicitly. Plain `clawscan` is
invalid so local runs do not accidentally use ClawHub's production profile.

Run one scanner across discovered skills:

```bash
clawscan --scanner skillspector
```

Run scanners that require credentials by exporting env vars next to the command:

```bash
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
clawscan --scanner ai-infra-guard

export SNYK_TOKEN=...
clawscan --scanner snyk
```

Run the built-in `clawhub` profile. This runs the ClawHub scanner suite and the
bundled ClawHub Codex judge harness:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...
clawscan --profile clawhub
```

Unless `--json` is passed, ClawScan writes the full artifact to
`./clawscan-results.json` by default, prints a concise key/value summary, and
ends with the full results path. Use `--output <path>` to choose a different
artifact path.

To use another built-in profile over the same discovered skill targets:

```bash
clawscan --profile skills-sh
```

Built-in profiles:

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |
| `skills-sh` | `socket`, `snyk` | none |

Gen Agent Trust Hub runs on skills.sh skills, but is omitted from ClawScan's
`skills-sh` profile because Gen does not provide a local CLI for ClawScan to
invoke.

The embedded `clawhub` profile owns ClawHub's prompt and output schema inside
ClawScan. ClawHub can run the same setup by invoking this profile.

If no target is passed with `--scanner`, `--profile`, or `--config`, ClawScan
discovers child skill directories under `./skills`. If `./skills` is missing or
has no child directories containing `SKILL.md`, ClawScan exits with a
target-discovery error. Pass an explicit target when you want to scan something
else.

## Project Profiles

ClawScan ships embedded built-in profiles, and projects can define their own in
the nearest `.clawscan.yml` or `.clawscan.yaml` discovered from the current
working directory upward. If both filenames exist in the same directory, the CLI
fails with an ambiguity error.

```yaml
version: 1

profiles:
  clawhub-release:
    scanners:
      - clawscan-static
    json: true

  skills-sh-review:
    scanners:
      - skillspector
      - clawscan-static
    output: ./clawscan-results/skills-sh-review.json
    judge:
      command: judge --out {{ output }}
      requiredEnv:
        - OPENAI_API_KEY
```

Run a project profile:

```bash
clawscan ./my-skill --profile clawhub-release
```

Load one specific config file and run every profile in it:

```bash
clawscan ./my-skill --config ./security/clawscan.yml
```

Load one profile from a specific config file:

```bash
clawscan ./my-skill --config ./security/clawscan.yml --profile skills-sh-review
```

Project profile names shadow built-in names as whole-profile replacements. CLI
flags override the selected profile for one run:

```bash
clawscan ./my-skill --profile skills-sh --scanner clawscan-static
```

Passing `--scanner` without `--profile` creates an ad hoc scanner-only run, so
profile judges are not invoked accidentally.

Config files may declare env var names that a judge needs, but they must not
store secret values. Scanner and judge credentials stay in environment
variables, such as `OPENAI_API_KEY` for the example judge command.
The built-in `skills-sh` profile needs `SOCKET_TOKEN` and `SNYK_TOKEN`
unless those scanners are supplied through `--scanner-result` fixtures or
overridden with `--scanner`.

## Explicit Target Scan

Scan a local skill directory with the built-in static scanner:

```bash
clawscan ./my-skill --scanner clawscan-static
```

Run multiple scanners and save the artifact:

```bash
clawscan ./my-skill \
  --scanner clawscan-static \
  --scanner skillspector \
  --scanner virustotal \
  --output ./clawscan-run.json
```

## Environment Variables

Secrets must be set with environment variables, not CLI flags:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...
export SNYK_TOKEN=...
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
```

ClawScan validates required env vars before starting a run and records only
whether each value was present:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Actual secret values are never written to run artifacts.

## Common Flags

| Flag | Description |
| --- | --- |
| `--profile <name>` | Profile to run. Use `--profile clawhub` for ClawHub parity. |
| `--config <path>` | Load one config file instead of discovering `.clawscan.yml` / `.clawscan.yaml`; omit `--profile` to run every profile in that file. |
| `--scanner <id>` | Scanner to run. Repeat for multiple scanners. |
| `--scanner-result <id=path>` | Use a JSON fixture instead of running that scanner. |
| `--output <path>` | Write the full artifact JSON to a specific file. Defaults to `./clawscan-results.json` when `--json` is not passed. |
| `--json` | Print the full artifact JSON to stdout and skip the default output file. |
| `--judge <cmd>` | Run an optional external judge harness. |
| `--benchmark [id]` | Run a supported benchmark instead of one target. Defaults to SkillTrustBench. |
| `--split <name>` | Benchmark split. Defaults to `benchmark` for SkillTrustBench and `eval_holdout` for OpenClaw. |
| `--limit <n>` | Maximum benchmark rows to run. `0` means all rows. |
| `--offset <n>` | Benchmark row offset. Defaults to `0`. |

## Help Output

```bash
clawscan --help
clawscan --version
```
