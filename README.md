# ClawScan

ClawScan lets the community see, test, and improve how ClawHub detects
malicious skills.

ClawScan is an open, benchmarkable security scanning harness for agent skills.
It gives researchers, contributors, and maintainers one small command for
running scanners, preserving their raw evidence, and optionally passing that
evidence into an external judge harness.

The goal is to make ClawHub's skill security process transparent and improvable:
anyone should be able to inspect the current scan setup, try different scanner
and judge combinations, and propose fixes that catch missed malicious skills
without creating broad false positives.

## Motivation

The agent-skill scanner space is moving quickly. New scanners are appearing,
existing scanners are changing their threat models, and no single scanner should
be treated as ground truth.

ClawScan exists to make that messy comparison work boring:

- Run several scanners against the same skill with one command.
- Preserve each scanner's raw JSON evidence instead of forcing one normalized
  verdict too early.
- Compare scanner output side by side.
- Iterate on a judge prompt, output schema, and harness command without
  rewriting scanner glue.
- Reproduce ClawHub's current ClawScan prompt path char-for-char when needed.
- Keep secrets out of CLI flags, shell history, process lists, and run artifacts.

ClawScan is intentionally CLI-first. V1 does not require a YAML config file or a
plugin API. Those can come later if repeated runs need more structure.

## Status

This repository currently contains the Go CLI foundation:

- argument parsing
- scanner ID validation
- environment-variable validation
- secret-safe run artifacts
- real SkillSpector execution
- external judge harness execution
- prompt interpolation for scanner JSON and target files
- deterministic scanner-result fixtures for reproducible prompt checks
- benchmark execution for `OpenClaw/clawhub-security-signals`
- ClawHub prompt parity proof tooling

Scanner adapters are being filled in incrementally. SkillSpector, AgentVerus,
Tencent AI-Infra-Guard, Cisco, Snyk, VirusTotal, Gen Digital URL lookups, and
the built-in static scanner execute today.

## Supported Scanners

These scanner IDs are accepted by the CLI today:

| Scanner ID | Source | Notes |
| --- | --- | --- |
| `agentverus` | [AgentVerus](https://agentverus.ai/) | Agent skill scanner with CLI JSON output. Runs through `npx --yes agentverus-scanner scan <target> --json`; no env var is required for the local scanner path. |
| `ai-infra-guard` | [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Self-hosted A.I.G taskapi integration for MCP Server & Agent Skills scan. Requires `AIG_BASE_URL`, `AIG_MODEL`, and `AIG_MODEL_API_KEY`. Local file/directory targets are zipped, uploaded to `/api/v1/app/taskapi/upload`, submitted as `mcp_scan`, polled through `/api/v1/app/taskapi/status/{id}`, and stored from `/api/v1/app/taskapi/result/{id}`. This project integrates AI-Infra-Guard, open-sourced by Tencent Zhuque Lab. |
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Security scanner for AI agent skills. Runs locally by default with `--no-llm`; set `CLAWSCAN_SKILLSPECTOR_LLM=1` to opt into provider-backed SkillSpector analysis. |
| `snyk` | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Snyk's scanner for AI agents, MCP servers, and skills. Requires `SNYK_TOKEN`. Runs through `uvx snyk-agent-scan@latest scan --json --no-bootstrap --skills <target>` so ClawScan scans the requested skill file or directory instead of full-machine auto-discovery. |
| `cisco` | [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Cisco's agent skill scanner. Runs through `skill-scanner scan <target> --format json --output <tempfile>`. No env var is required by ClawScan itself for this v1 path; upstream analyzer configuration is handled by Cisco's CLI. |
| `virustotal` | [VirusTotal API](https://docs.virustotal.com/reference/file) | File reputation and malware telemetry. Requires `VIRUSTOTAL_API_KEY`. V1 hashes single-file targets with SHA-256 and queries the VirusTotal v3 file report endpoint by hash; directory targets return a scanner-specific `skipped` result. |
| `gendigital` | [Gen Digital Skill Scanner](https://ai.gendigital.com/skill-scanner) | Public lookup-style scanner for ClawHub skill URLs. V1 supports URL targets only; local paths return a scanner-specific `skipped` result. |
| `static` | Built in | Lightweight local static scanner for skill artifacts. |

The built-in `static` scanner stores deterministic raw JSON with scanner
metadata, `files.scanned`, `files.omitted`, and `findings`. It records evidence
only; it does not emit a final policy verdict.

The `snyk` scanner stores JSON stdout from Snyk Agent Scan as
`scanners.snyk.raw`. `SNYK_TOKEN` is read from the environment by Snyk's CLI and
is never passed as a ClawScan CLI flag or recorded in run artifacts.

The `ai-infra-guard` scanner stores a raw JSON evidence object with the A.I.G
upload response, task session, final status, and task result. Configure
`AIG_BASE_URL` to point at a running self-hosted AI-Infra-Guard service.
`AIG_MODEL` and `AIG_MODEL_API_KEY` are passed to A.I.G's `mcp_scan` task as the
analysis model; `AIG_MODEL_BASE_URL` defaults to `https://api.openai.com/v1`.
`AIG_API_KEY` is optional and sent as the A.I.G taskapi `API-KEY` header when
present. `AIG_USERNAME` defaults to `openclaw`. Optional non-secret tuning env
vars are `AIG_SCAN_LANGUAGE`, `AIG_SCAN_PROMPT` for local archive scans,
`AIG_SCAN_THREAD_COUNT`, `AIG_POLL_INTERVAL_MS`, and
`AIG_POLL_MAX_ATTEMPTS`.

The `cisco` scanner stores the raw Cisco AI Defense skill-scanner JSON output
file as `scanners.cisco.raw`. ClawScan does not pass Cisco analyzer credentials
as CLI flags; configure Cisco's CLI through its own environment variables when
using analyzer-backed modes.

The `virustotal` scanner stores the raw VirusTotal JSON response as
`scanners.virustotal.raw` when the API returns JSON. It never uploads target
bytes in v1; it reads a single regular file locally, hashes the bytes with
SHA-256, and performs a file report lookup by hash. Directories are intentionally
unsupported until ClawScan has a deterministic archive format for that target
shape.

The `gendigital` scanner stores the raw Gen Digital lookup JSON response as
`scanners.gendigital.raw` when the API returns JSON. It posts URL targets to
Gen Digital's public lookup endpoint with a JSON `skillUrl` body and does not
require an API key. Local path targets are not uploaded or fetched in v1; they
return a scanner-specific `skipped` result explaining that Gen Digital requires
a ClawHub skill URL target.

Planned scanners should not be added to this table until the CLI accepts their
scanner ID.

## Install

Once ClawScan is published from the `github.com/openclaw/clawscan` module:

```bash
go install github.com/openclaw/clawscan/cmd/clawscan@latest
```

For local development from the repository root:

```bash
go install ./cmd/clawscan
```

For local development, run without installing:

```bash
go run ./cmd/clawscan ./my-skill --scanner skillspector --json
```

Print build metadata:

```bash
clawscan --version
```

Local development builds report `dev`, `unknown` commit, and `unknown` build
date unless those fields are set with Go linker flags.

## Release Packaging

Release artifacts are built with Go only. No package manager, secrets, or remote
repository access is required.

```bash
make release VERSION=v0.1.0
```

The release target writes archives to `dist/`:

- `clawscan_<version>_darwin_amd64.tar.gz`
- `clawscan_<version>_darwin_arm64.tar.gz`
- `clawscan_<version>_linux_amd64.tar.gz`
- `clawscan_<version>_linux_arm64.tar.gz`
- `clawscan_<version>_windows_amd64.zip`
- `checksums.txt` with SHA-256 checksums from `shasum -a 256`

Each archive contains the `clawscan` binary and this README. The release build
sets `--version` metadata with:

```bash
-ldflags "-X main.version=<version> -X main.commit=<git-sha> -X main.date=<utc-build-time>"
```

## Secrets

Secrets must be provided through environment variables, not CLI flags.

```bash
export VIRUSTOTAL_API_KEY=...
export SNYK_TOKEN=...
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export NVIDIA_INFERENCE_KEY=...
export CLAWSCAN_SKILLSPECTOR_LLM=1
```

ClawScan validates required variables before starting a run. Missing variables
are grouped into one error:

```txt
Missing required environment variables:

- VIRUSTOTAL_API_KEY required by scanner virustotal
- AIG_BASE_URL required by scanner ai-infra-guard
- AIG_MODEL required by scanner ai-infra-guard
- AIG_MODEL_API_KEY required by scanner ai-infra-guard
```

Run artifacts record only whether a variable was present:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Actual secret values are never written to the artifact.

`CLAWSCAN_SKILLSPECTOR_LLM=1` is not a secret. It is an explicit opt-in for
SkillSpector's provider-backed LLM analysis. When enabled with the default
OpenAI-compatible provider, `OPENAI_API_KEY` is required. For SkillSpector's
documented provider modes, use `SKILLSPECTOR_PROVIDER=anthropic` with
`ANTHROPIC_API_KEY`, or `SKILLSPECTOR_PROVIDER=nv_inference` / `nv_build` with
`NVIDIA_INFERENCE_KEY`.

Judge harness credentials are owned by the command you pass to `--judge`.
ClawScan does not add model-provider API keys to its own CLI flags or artifacts.

## Usage

```bash
clawscan <target> --scanner <scanner-id> [flags]
clawscan --benchmark OpenClaw/clawhub-security-signals --scanner <scanner-id> [flags]
```

`<target>` is usually the path to the skill directory or skill file to scan.
Some scanners can support URL targets when their upstream scanner is a public
lookup service. In v1, `gendigital` uses this shape for ClawHub skill URLs:

```bash
clawscan https://clawhub.ai/author/skill-name \
  --scanner gendigital \
  --json
```

`ai-infra-guard` also supports URL targets through A.I.G's `mcp_scan` taskapi:

```bash
clawscan https://github.com/example/ai-tool \
  --scanner ai-infra-guard \
  --json
```

URL targets are recorded as `"target.kind": "url"` in the run artifact. Local
file copying for judge workspaces and `{{ target.files }}` remains path-based
and may fail clearly for URL targets.

### Benchmarks

ClawScan can also run the same scanner/judge setup over the OpenClaw security
signals benchmark:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner static \
  --output ./clawscan-benchmark.json
```

V1 intentionally supports only `OpenClaw/clawhub-security-signals`. The loader
maps each Hugging Face row into a temporary skill directory by writing
`skill_md_content` to `SKILL.md` and restoring files from
`skill_bundle_content`. It then runs the normal ClawScan path for that row, so
scanner output, prompt rendering, judge execution, env validation, and secret
redaction stay consistent with one-off scans.

`--split` selects a reproducible Hugging Face split. The default is
`eval_holdout`; accepted splits are `train`, `validation`, `test`, and
`eval_holdout`. Use `--limit` and `--offset` for reproducible chunks while
iterating locally. A limit of `0` means run the whole split.

### Flags

| Flag | Required | Repeatable | Description |
| --- | --- | --- | --- |
| `--scanner <id>` | Yes | Yes | Scanner to run. Accepted IDs are listed above. |
| `--scanner-result <id=path>` | No | Yes | Use a JSON fixture as the scanner result instead of running that scanner. The scanner must also be listed with `--scanner`. |
| `--output <path>` | No | No | Write the run artifact JSON to a file. |
| `--json` | No | No | Print the run artifact JSON to stdout. |
| `--judge <cmd>` | No | No | External judge harness command. ClawScan interpolates placeholders, runs it through the platform shell (`/bin/sh -c` on Unix, `cmd.exe /C` on Windows), and records its JSON output. |
| `--benchmark <id>` | No | No | Run a supported benchmark instead of a single target. V1 supports `OpenClaw/clawhub-security-signals`. |
| `--split <name>` | No | No | Benchmark split. Defaults to `eval_holdout`. |
| `--limit <n>` | No | No | Maximum benchmark rows to run. `0` means all rows. |
| `--offset <n>` | No | No | Benchmark row offset. Defaults to `0`. |

If `--judge` is omitted, ClawScan only runs scanners and writes their raw
results. If `--judge` is present, the command must produce a JSON object either
at `{{ output }}` or on stdout.

### Judge Placeholders

`--judge` supports these placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary judge workspace. It contains `artifact/` with copied target files, `scanners/<id>.json` with raw scanner results, and `metadata.json` with target/scanner metadata plus copied/omitted target-file records. |
| `{{ prompt }}` | Render `./prompt.md`, write it to the workspace, and interpolate the rendered prompt path. |
| `{{ prompt:<path> }}` | Render a specific prompt template path instead of `./prompt.md`. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and interpolate that copied schema path. |
| `{{ output_schema:<path> }}` | Copy a specific schema path instead of `./schema.json`. |
| `{{ output }}` | Path where the judge command should write its final JSON result. |

Prompt templates can use scanner placeholders such as
`{{ scanners.skillspector }}` and `{{ scanners.virustotal }}`. ClawScan renders
those before the judge command runs.

## Sample Commands

Run one scanner and print JSON:

```bash
clawscan ./my-skill \
  --scanner agentverus \
  --json
```

Run several scanners and save the artifact:

```bash
clawscan ./my-skill \
  --scanner agentverus \
  --scanner ai-infra-guard \
  --scanner skillspector \
  --scanner cisco \
  --scanner snyk \
  --scanner virustotal \
  --output ./clawscan-run.json
```

Run Tencent AI-Infra-Guard through a local A.I.G service:

```bash
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...

clawscan ./my-skill \
  --scanner ai-infra-guard \
  --json
```

Run scanner comparison with a Codex judge harness:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner virustotal \
  --scanner static \
  --judge 'codex exec --cd {{ workspace }} \
    --model gpt-5.5 \
    --sandbox read-only \
    --skip-git-repo-check \
    --ignore-user-config \
    -c approval_policy=never \
    -c model_reasoning_effort=high \
    --output-schema {{ output_schema:./schemas/security-verdict.schema.json }} \
    --output-last-message {{ output }} \
    --ephemeral \
    --json \
    - < {{ prompt:./prompts/security-review.md }}' \
  --output ./clawscan-judged.json
```

Run the ClawHub prompt parity proof against a local ClawHub checkout:

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /path/to/clawhub \
  --out /tmp/clawhub-prompt-parity-proof-go.json \
  --out-system-prompt /tmp/clawhub-system.md \
  --out-prompt /tmp/clawhub-prompt.md \
  --out-output-schema /tmp/clawhub-output.schema.json \
  --out-request /tmp/clawhub-request.json \
  --out-skillspector-result /tmp/clawhub-skillspector.json \
  --out-virustotal-result /tmp/clawhub-virustotal.json
```

The parity proof compares the Go-rendered prompt against the current ClawHub
TypeScript worker output char-for-char and records the prompt length, SHA-256,
and whether SkillSpector evidence was supplied through the runtime input path.
It also exports the full Codex stdin prompt, output schema, and scanner-result
fixture files for the main CLI. The exported prompt is a normal ClawScan prompt
template with `{{ scanners.skillspector }}` and `{{ scanners.virustotal }}`
placeholders.

Run the exported prompt files through the main CLI with a no-op judge command:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner-result skillspector=/tmp/clawhub-skillspector.json \
  --scanner virustotal \
  --scanner-result virustotal=/tmp/clawhub-virustotal.json \
  --judge 'printf "{\"ok\":true}\n" > {{ output }} # {{ prompt:/tmp/clawhub-prompt.md }} {{ output_schema:/tmp/clawhub-output.schema.json }}' \
  --output /tmp/clawscan-clawhub-prompt-proof.json
```

This records `judge.status`, `judge.promptSha256`, and
`judge.outputSchemaSha256` without spending a model call. For ClawHub parity,
`judge.promptSha256` should match the verifier's `combinedPromptSha256`.
`--scanner-result` is intentionally explicit so parity checks can use stable
scanner evidence instead of live scanner output that may change over time.

## Artifact Shape

A run writes a `clawscan-run-v1` JSON artifact:

```json
{
  "schemaVersion": "clawscan-run-v1",
  "target": {
    "kind": "skill",
    "input": "./my-skill",
    "resolvedPath": "/absolute/path/to/my-skill"
  },
  "startedAt": "2026-06-03T00:00:00Z",
  "completedAt": "2026-06-03T00:00:01Z",
  "env": {
    "VIRUSTOTAL_API_KEY": "present"
  },
  "scanners": {
    "virustotal": {
      "status": "skipped",
      "startedAt": "2026-06-03T00:00:00Z",
      "completedAt": "2026-06-03T00:00:01Z",
      "command": [
        "virustotal",
        "file-report"
      ],
      "error": "VirusTotal scanner supports single-file targets in v1; directory targets are unsupported.",
      "raw": null
    }
  },
  "judge": null
}
```

The important design choice is that scanner output remains raw evidence. The
judge harness decides how to interpret it.

A benchmark run writes a `clawscan-benchmark-v1` JSON artifact:

```json
{
  "schemaVersion": "clawscan-benchmark-v1",
  "benchmark": {
    "id": "OpenClaw/clawhub-security-signals",
    "source": "huggingface",
    "config": "default",
    "split": "eval_holdout",
    "offset": 0,
    "limit": 1,
    "rows": 1
  },
  "startedAt": "2026-06-03T00:00:00Z",
  "completedAt": "2026-06-03T00:00:01Z",
  "env": {},
  "cases": [
    {
      "id": "dataset-row-id",
      "skillSlug": "owner/skill",
      "skillVersion": "1.0.0",
      "expected": {
        "verdict": "suspicious",
        "confidence": "high",
        "model": "gpt-5.5",
        "summary": "Dataset verdict summary."
      },
      "run": {
        "schemaVersion": "clawscan-run-v1",
        "target": {
          "kind": "skill",
          "input": "/tmp/clawscan-benchmark-.../skill",
          "resolvedPath": "/tmp/clawscan-benchmark-.../skill"
        },
        "startedAt": "2026-06-03T00:00:00Z",
        "completedAt": "2026-06-03T00:00:01Z",
        "env": {},
        "scanners": {
          "static": {
            "status": "completed",
            "startedAt": "2026-06-03T00:00:00Z",
            "completedAt": "2026-06-03T00:00:01Z",
            "command": [
              "clawscan",
              "static"
            ],
            "error": "",
            "raw": {}
          }
        },
        "judge": null
      }
    }
  ],
  "summary": {
    "caseCount": 1,
    "expectedVerdicts": {
      "suspicious": 1
    },
    "scannerStatuses": {
      "static": {
        "completed": 1
      }
    }
  }
}
```

Each benchmark case embeds the normal one-off `clawscan-run-v1` artifact for
that row.

## Judge Harness

The intended judge flow is:

1. Run requested scanners.
2. Wait for all scanner results.
3. Prepare a temporary judge workspace.
4. Render any prompt referenced by `{{ prompt }}` or `{{ prompt:<path> }}`.
5. Copy any schema referenced by `{{ output_schema }}` or
   `{{ output_schema:<path> }}`.
6. Interpolate placeholders into `--judge`.
7. Run the judge command through the platform shell (`/bin/sh -c` on Unix,
   `cmd.exe /C` on Windows) and store its JSON result alongside scanner
   evidence.

Prompt authors should place scanner evidence explicitly:

````md
SkillSpector evidence:

```json
{{ scanners.skillspector }}
```

VirusTotal evidence:

```json
{{ scanners.virustotal }}
```
````

Target files can also be included:

````md
Skill files:

{{ target.files }}
````

If a prompt references a scanner that was not requested, ClawScan should fail
clearly rather than silently inserting an empty block.

## Development

Run tests:

```bash
go test ./...
go vet ./...
```

Run the current CLI smoke tests manually without scanner credentials:

```bash
go run ./cmd/clawscan ./README.md \
  --scanner static \
  --output /tmp/clawscan-smoke.json

go run ./cmd/clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 1 \
  --scanner static \
  --output /tmp/clawscan-benchmark-smoke.json
```

Check the prompt parity proof:

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /Users/patrickerichsen/.codex/worktrees/67c6/clawhub \
  --out /tmp/clawhub-prompt-parity-proof-go.json
```
