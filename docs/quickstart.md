# Quickstart

## Install

Homebrew is the recommended install path on macOS and Linux:

```bash
brew install openclaw/tap/clawscan
```

For Node-based CI or cross-platform automation, install the npm package:

```bash
npm install -g @openclaw/clawscan
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

## Scanner Dependencies

List available scanners and inspect one scanner before installing or running it:

```bash
clawscan scanners
clawscan scanners skillspector
```

Command-backed scanners and judges run in ClawScan's Docker runtime by default.
Keep Docker running for local scans. Install or verify local scanner
dependencies only when you intentionally run with `--sandbox off`:

```bash
clawscan install cisco skillspector
```

The install command accepts one or more scanner IDs and prints one concise
status per scanner. It uses the install commands published by each scanner's
upstream docs where available, verifies launcher-only tools such as `uvx`, and
skips built-in or API-backed scanners that have no local CLI to install.

Cisco's upstream README recommends `uv pip install cisco-ai-skill-scanner` for
the base scanner package, so it uses the same Python environment context as the
Cisco docs. Socket and AgentVerus use npm-based installs, and AgentVerus'
upstream install is a project-local dev dependency.

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
`./clawscan-results/artifact.json` by default, preserves per-scanner JSON files
in the same results directory, prints a concise key/value summary, and ends
with the full results path. Use `--output <path>` to choose a different
artifact path; explicit `.json` paths keep that artifact file and write scanner
JSON beside it.

To use another built-in profile over the same discovered skill targets:

```bash
clawscan --profile skills-sh
```

Built-in profiles:

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |
| `skills-sh` | `socket`, `snyk` | none |

Inspect the resolved profile catalog, including nearest project-local profiles:

```bash
clawscan profiles
clawscan profiles -v
```

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

sandbox:
  mode: docker
  image: ghcr.io/openclaw/clawscan-runtime:latest
  env:
    - OPENAI_API_KEY

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
    sandbox:
      env:
        - ANTHROPIC_API_KEY
    judge:
      command: judge --out {{ output }}
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

Config files must not store secret values. Scanner and judge credentials stay
in environment variables, such as `OPENAI_API_KEY` for the example judge
command. Use `sandbox.env` to allow judge-specific environment variables into
the Docker runtime.
The built-in `skills-sh` profile needs `SOCKET_CLI_API_TOKEN` and `SNYK_TOKEN`
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
export SOCKET_CLI_API_TOKEN=...
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

## Benchmark Catalog

Inspect supported benchmarks before choosing a benchmark ID and `--split`
value:

```bash
clawscan benchmark list
clawscan benchmark SkillTrustBench --limit 1 --scanner clawscan-static --json
```

## Common Flags

| Flag | Description |
| --- | --- |
| `--profile <name>` | Profile to run. Use `--profile clawhub` for ClawHub parity. |
| `--config <path>` | Load one config file instead of discovering `.clawscan.yml` / `.clawscan.yaml`; omit `--profile` to run every profile in that file. |
| `--scanner <id>` | Scanner to run. Repeat for multiple scanners. |
| `--scanner-result <id=path>` | Use a JSON fixture instead of running that scanner. |
| `--output <path>` | Write the full artifact JSON to a specific file. Defaults to `./clawscan-results/artifact.json` when `--json` is not passed. Explicit `.json` paths keep that artifact file and write scanner JSON beside it. |
| `--json` | Print the full artifact JSON to stdout and skip default file writes unless `--output` is also passed. |
| `--judge <cmd>` | Run an optional external judge harness. |
| `--sandbox <docker\|off>` | Select command sandbox mode. Defaults to Docker. |
| `--sandbox-image <image>` | Override the Docker runtime image. |
| `--sandbox-env <name>` | Allow an environment variable into the Docker runtime. Repeat for multiple variables. |
| `clawscan benchmark <id>` | Run a supported benchmark instead of one target. |
| `--split <name>` | Benchmark split. Defaults to `benchmark` for SkillTrustBench and `eval_holdout` for ClawHub Security Signals. |
| `--limit <n>` | Maximum benchmark rows to run. `0` means all rows. |
| `--offset <n>` | Benchmark row offset. Defaults to `0`. |

## Help Output

```bash
clawscan --help
clawscan --version
```
