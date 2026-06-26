# ClawScan

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/ci.yml?query=branch%3Amain)
[![Release](https://img.shields.io/badge/Release-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/badge/latest%20release-unreleased-lightgrey)](https://github.com/openclaw/clawscan/releases)

ClawScan is an open, benchmarkable security scanning harness for agent skills.

It runs one or more scanners, preserves their raw evidence, and can hand that
evidence to a judge harness you choose. Use it to compare scanners, iterate on
prompts and schemas, and regression-test skill security checks without wiring
every scanner together yourself.

OpenClaw uses ClawScan to make ClawHub's production skill scanning visible and
improvable, but the CLI is general purpose: any researcher, maintainer, or
project can use it for agent-skill security scanning.

## Quick Start

From a repository root with skills under `./skills/<name>/SKILL.md`, choose a
scanner, profile, config, or benchmark explicitly. Plain `clawscan` is invalid
so local runs do not accidentally use ClawHub's production profile.

Run SkillSpector and Snyk across discovered skills:

```bash
export OPENAI_API_KEY=...
export SNYK_TOKEN=...
clawscan --scanner skillspector --scanner snyk
```

Run AI-Infra-Guard across discovered skills:

```bash
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
clawscan --scanner ai-infra-guard
```

Run the built-in `clawhub` profile. This runs the ClawHub scanner suite and the
bundled ClawHub Codex judge harness:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...
clawscan --profile clawhub
```

Run a local static scan against one explicit target and print the artifact:

```bash
go run ./cmd/clawscan ./my-skill --scanner clawscan-static --json
```

Run a built-in profile against one explicit target:

```bash
clawscan ./my-skill --profile clawhub
```

If you only want raw scanner evidence with no judge, pass explicit scanners:

```bash
clawscan ./my-skill --scanner clawscan-static --scanner skillspector
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
the OpenClaw security-signals benchmark. The `clawscan-benchmark.json` artifact
is the primary result to inspect; ClawScan can also derive a lightweight
`predictions.jsonl` file for leaderboard and CI submission plumbing.

Unless `--json` is passed, ClawScan writes the full artifact to
`./clawscan-results.json` by default, prints a concise key/value summary, and
ends with the full results path. Use `--output <path>` to choose a different
artifact path.

## Example: Malicious Skill Output

[Trail of Bits](https://www.trailofbits.com/) publishes
[overtly-malicious-skills](https://github.com/trailofbits/overtly-malicious-skills),
a fixture repository of intentionally malicious agent skills. Do not install or
run these skills; use them as scanner fixtures only.

Clone the fixture repo and pin the exact revision used for this example:

```bash
git clone https://github.com/trailofbits/overtly-malicious-skills.git /tmp/overtly-malicious-skills
cd /tmp/overtly-malicious-skills
git checkout 4ffbf9461ef0505f9ce76a0d3694a18ec33ea531
```

Run the ClawHub profile, which is the scan recipe ClawHub consumes:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...

clawscan ./skills/csv-summarizer --profile clawhub
```

Run the skills-sh comparison profile over the same target:

```bash
export SOCKET_TOKEN=...
export SNYK_TOKEN=...

clawscan ./skills/csv-summarizer --profile skills-sh
```

For a scanner-evidence example, run SkillSpector by itself:

```bash
export OPENAI_API_KEY=...
clawscan ./skills/csv-summarizer \
  --scanner skillspector \
  --json |
  jq '.scanners.skillspector.raw | {
    score: .risk_assessment.score,
    severity: .risk_assessment.severity,
    recommendation: .risk_assessment.recommendation,
    issues: [.issues[] | {id, category, severity, file: .location.file, line: .location.start_line, finding}]
  }'
```

Abbreviated real output from that pinned revision:

```json
{
  "score": 31,
  "severity": "MEDIUM",
  "recommendation": "CAUTION",
  "issues": [
    {
      "id": "LP3",
      "category": "MCP Least Privilege",
      "severity": "MEDIUM",
      "file": "SKILL.md",
      "line": 1,
      "finding": null
    },
    {
      "id": "E2",
      "category": "Data Exfiltration",
      "severity": "HIGH",
      "file": "scripts/summarize.py",
      "line": 100014,
      "finding": "for key, value in os.environ.items()"
    }
  ]
}
```

## What It Does

- Runs explicitly selected scanner adapters, profiles, or configs against
  discovered `./skills` targets, one explicit skill target, or a supported
  benchmark.
- Keeps scanner output as raw JSON evidence.
- Records scanner status, errors, commands, and secret-safe env presence.
- Optionally invokes an external judge command through `--judge`.
- Lets prompts interpolate scanner JSON with placeholders such as
  `{{ scanners.skillspector }}`.

If no target is passed with `--scanner`, `--profile`, or `--config`, ClawScan
looks for child skill directories under `./skills`. If that directory is
missing or contains no child directories with a `SKILL.md`, the CLI exits with
a clear target-discovery error instead of silently scanning `.`. Plain
`clawscan` without `--scanner`, `--profile`, `--config`, or `--benchmark`
exits before target discovery and asks for an explicit selection.

Profiles can come from the embedded built-ins or from the nearest project-local
`.clawscan.yml` / `.clawscan.yaml`. Project profiles shadow built-in profile
names, and CLI flags such as `--scanner`, `--output`, `--json`, and `--judge`
override profile values for one command. Use `--config <path>` by itself to run
every profile in that config, or add `--profile <name>` to run just one profile
from that config.
Passing `--scanner` without `--profile` creates an ad hoc scanner-only run, so
profile judges are not invoked accidentally.

Built-in profiles:

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |
| `skills-sh` | `socket`, `snyk` | none |

Gen Agent Trust Hub runs on skills.sh skills, but is omitted from ClawScan's
`skills-sh` profile because Gen does not provide a local CLI for ClawScan to
invoke.

## Supported Scanners

Accepted scanner IDs:

```text
agentverus, ai-infra-guard, cisco, clawscan-static, skillspector, snyk, socket, virustotal
```

Some scanners require upstream tools or credentials. Secrets must come from
environment variables, never CLI flags:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...
export SOCKET_TOKEN=...
export SNYK_TOKEN=...
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
```

## Sandbox Runtime

ClawScan runs command-backed scanners and judge commands through Docker by
default. The runtime image is `ghcr.io/openclaw/clawscan-runtime:latest`, which
is built to contain the built-in scanner CLIs plus Codex and Claude Code for
judge/profile commands, so users do not need to install those tools on the host.

The Docker sandbox keeps network access on for scanner APIs, mounts only the
target/work/output paths needed by the command, and passes only the declared env
var names for the selected scanners or profile judge. ClawScan records env
presence as `present` or `missing`; it never writes secret values to artifacts.

Use the opt-out only when the surrounding environment is already isolated, such
as a locked-down CI worker where Docker is unavailable:

```bash
clawscan ./my-skill --scanner skillspector --sandbox off
CLAWSCAN_SANDBOX=off clawscan ./my-skill --scanner skillspector
```

CI runners can smoke-test Docker support with:

```bash
docker version
docker run --rm ghcr.io/openclaw/clawscan-runtime:latest skillspector --help
```

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

Print build metadata:

```bash
clawscan --version
```

## Documentation

The detailed manual lives in [`docs/`](docs/index.md):

- [Quickstart](docs/quickstart.md)
- [Contributing](docs/contributing.md)
- [Scanners](docs/scanners.md)
- [Judge harness](docs/judge.md)
- [Benchmarks](docs/benchmarks.md)
- [Artifacts](docs/artifacts.md)
- [Improving ClawHub scans](docs/improving-clawhub-scans.md)
- [Development](docs/development.md)
- [Releasing](docs/releasing.md)

Build the static docs site locally:

```bash
make docs-site
open dist/docs-site/index.html
```

GitHub Pages publishes the docs site from `docs/` on pushes to `main`.

## Roadmap

- Command-backed custom scanner adapters, so teams can add their own scanner
  commands through a documented adapter contract once the built-in scanner
  boundary has settled.
- Version-pinned Docker runtime image tags that pair each ClawScan release with
  a reviewed scanner toolchain.

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

Build and smoke test the npm package:

```bash
make npm-package VERSION=v0.1.0
```

Release artifacts are written to `dist/`.

## Release Versioning

ClawScan does not have a published `v*` tag or GitHub Release yet, so the latest
release badge intentionally reports `unreleased`. For the first release, run the
local gate, push a semver tag such as `v0.1.0`, and let the `Release` workflow
build archives with `make release VERSION=<tag>`, publish the GitHub Release,
and dispatch the Homebrew tap update. The CLI prints the tag, commit, and build
date from release ldflags with `clawscan --version`.
