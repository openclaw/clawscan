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
default built-in `clawhub` profile. This runs the ClawHub scanner suite and the
bundled ClawHub Codex judge harness:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...
clawscan
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

Run the default ClawHub profile, which is the scan recipe ClawHub consumes:

```bash
export VIRUSTOTAL_API_KEY=...
export OPENAI_API_KEY=...

clawscan ./skills/csv-summarizer
```

Run the skills-sh comparison profile over the same target:

```bash
export SOCKET_TOKEN=...
export SNYK_TOKEN=...

clawscan ./skills/csv-summarizer --profile skills-sh
```

For a quick, secretless scanner-evidence example, run SkillSpector by itself:

```bash
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
