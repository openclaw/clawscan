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

Run a local static scan and print the artifact:

```bash
go run ./cmd/clawscan ./my-skill --scanner clawscan-static --json
```

Run several scanners and save the result:

```bash
clawscan ./my-skill \
  --scanner clawscan-static \
  --scanner skillspector \
  --scanner virustotal \
  --output ./clawscan-run.json
```

Run the supported benchmark:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

## What It Does

- Runs scanner adapters against one skill target or a supported benchmark.
- Keeps scanner output as raw JSON evidence.
- Records scanner status, errors, commands, and secret-safe env presence.
- Optionally invokes an external judge command through `--judge`.
- Lets prompts interpolate scanner JSON with placeholders such as
  `{{ scanners.skillspector }}`.

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
