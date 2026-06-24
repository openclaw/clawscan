# ClawScan

ClawScan is an open, benchmarkable security scanning harness for agent skills.

It runs one or more scanners, preserves their raw evidence, and can hand that
evidence to a judge harness you choose. Use it to compare scanners, iterate on
prompts and schemas, and regression-test skill security checks without wiring
every scanner together yourself.

OpenClaw uses ClawScan to make ClawHub's production skill scanning visible and
improvable, but the CLI is general purpose: any researcher, maintainer, or
project can use it for agent-skill security scanning.

## Quick Start

From a repository root with skills under `./skills/<name>/SKILL.md`, run the
default built-in `clawhub` profile:

```bash
clawscan
```

Run a local static scan against one explicit target and print the artifact:

```bash
go run ./cmd/clawscan ./my-skill --scanner clawscan-static --json
```

Run a built-in profile against one explicit target:

```bash
clawscan ./my-skill --profile clawhub --json
```

Run several scanners and save the result:

```bash
clawscan ./my-skill \
  --scanner clawscan-static \
  --scanner skillspector \
  --scanner virustotal \
  --output ./clawscan-run.json
```

Run the default benchmark, SkillTrustBench:

```bash
clawscan \
  --benchmark \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

Use `--benchmark OpenClaw/clawhub-security-signals --split eval_holdout` for
the OpenClaw security-signals benchmark. When that benchmark is run with
`--output`, ClawScan also writes a submission-friendly `predictions.jsonl` file
next to the benchmark artifact.

## What It Does

- Runs scanner adapters against discovered `./skills` targets, one explicit
  skill target, or a supported benchmark.
- Keeps scanner output as raw JSON evidence.
- Records scanner status, errors, commands, and secret-safe env presence.
- Optionally invokes an external judge command through `--judge`.
- Lets prompts interpolate scanner JSON with placeholders such as
  `{{ scanners.skillspector }}`.

If no target is passed, ClawScan looks for child skill directories under
`./skills`. If that directory is missing or contains no child directories with a
`SKILL.md`, the CLI exits with a clear target-discovery error instead of
silently scanning `.`.

Profiles can come from the embedded built-ins or from the nearest project-local
`.clawscan.yml` / `.clawscan.yaml`. Project profiles shadow built-in profile
names, and CLI flags such as `--scanner`, `--output`, `--json`, and `--judge`
override the selected profile for one run. Pair `--config <path>` with
`--profile <name>` to load one profile from a specific config file instead of
upward discovery.

## Supported Scanners

Accepted scanner IDs:

```text
agentverus, ai-infra-guard, cisco, clawscan-static, gendigital, skillspector, snyk, virustotal
```

Some scanners require upstream tools or credentials. Secrets must come from
environment variables, never CLI flags:

```bash
export VIRUSTOTAL_API_KEY=...
export SNYK_TOKEN=...
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
```

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

Print build metadata:

```bash
clawscan --version
```

## Documentation

The detailed manual lives in [`docs/`](docs/index.md):

- [Quickstart](docs/quickstart.md)
- [Scanners](docs/scanners.md)
- [Judge harness](docs/judge.md)
- [Benchmarks](docs/benchmarks.md)
- [Artifacts](docs/artifacts.md)
- [Development](docs/development.md)
- [Releasing](docs/releasing.md)

Build the static docs site locally:

```bash
make docs-site
open dist/docs-site/index.html
```

GitHub Pages publishes the docs site from `docs/` on pushes to `main`.

## Roadmap

- Reusable GitHub Action or workflow for CI. The goal is a copy-pasteable way
  to install ClawScan, install the dependencies needed by built-in scanners,
  run a selected profile or config, and upload the JSON artifact. Judge harness
  CLIs such as `codex` should stay explicit setup steps because `--judge` is an
  arbitrary command supplied by the workflow author.

## Development

Run the local checks:

```bash
go test ./...
go vet ./...
make docs-site
```

Build release archives:

```bash
make release VERSION=v0.1.0
```

Release artifacts are written to `dist/`.
