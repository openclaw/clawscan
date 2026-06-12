# ClawScan

ClawScan is a standalone security runner for OpenClaw skills. It gives us one
small command for running multiple skill scanners, collecting their raw evidence,
and optionally passing that evidence into an external judge harness.

The first goal is reproducibility: the open source tool should be able to run the
same ClawHub ClawScan setup we run internally, while making it easier for others
to compare scanners and iterate on their own judge prompts and harnesses.

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
- ClawHub prompt parity proof tooling

Scanner adapters are being filled in incrementally. SkillSpector, AgentVerus,
Cisco, Snyk, VirusTotal, Gen Digital URL lookups, and the built-in static
scanner execute today.

## Supported Scanners

These scanner IDs are accepted by the CLI today:

| Scanner ID | Source | Notes |
| --- | --- | --- |
| `agentverus` | [AgentVerus](https://agentverus.ai/) | Agent skill scanner with CLI JSON output. Runs through `npx --yes agentverus-scanner scan <target> --json`; no env var is required for the local scanner path. |
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Security scanner for AI agent skills. Runs locally by default with `--no-llm`; set `CLAWSCAN_SKILLSPECTOR_LLM=1` to opt into provider-backed SkillSpector analysis. |
| `snyk` | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Snyk's scanner for AI agents, MCP servers, and skills. Requires `SNYK_TOKEN`. Runs through `uvx snyk-agent-scan@latest --json --no-bootstrap --skills <target>` so ClawScan scans the requested skill file or directory instead of full-machine auto-discovery. |
| `cisco` | [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Cisco's agent skill scanner. Runs the local default analyzer path through `skill-scanner scan <target> --format json --output <tempfile>`. No env var is required for this v1 path; upstream LLM, AI Defense, and VirusTotal modes are not enabled by ClawScan. |
| `virustotal` | [VirusTotal API](https://docs.virustotal.com/reference/file) | File reputation and malware telemetry. Requires `VIRUSTOTAL_API_KEY`. V1 hashes single-file targets with SHA-256 and queries the VirusTotal v3 file report endpoint by hash; directory targets return a scanner-specific `skipped` result. |
| `gendigital` | [Gen Digital Skill Scanner](https://ai.gendigital.com/skill-scanner) | Public lookup-style scanner for ClawHub skill URLs. V1 supports URL targets only; local paths return a scanner-specific `skipped` result. |
| `static` | Built in | Lightweight local static scanner for skill artifacts. |

The built-in `static` scanner stores deterministic raw JSON with scanner
metadata, `files.scanned`, `files.omitted`, and `findings`. It records evidence
only; it does not emit a final policy verdict.

The `snyk` scanner stores JSON stdout from Snyk Agent Scan as
`scanners.snyk.raw`. `SNYK_TOKEN` is read from the environment by Snyk's CLI and
is never passed as a ClawScan CLI flag or recorded in run artifacts.

The `cisco` scanner stores the raw Cisco AI Defense skill-scanner JSON output
file as `scanners.cisco.raw`. ClawScan uses Cisco's default local scan mode only
in v1 and does not require or pass `SKILL_SCANNER_LLM_API_KEY`,
`AI_DEFENSE_API_KEY`, or `VIRUSTOTAL_API_KEY` for this adapter.

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
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export CLAWSCAN_SKILLSPECTOR_LLM=1
```

ClawScan validates required variables before starting a run. Missing variables
are grouped into one error:

```txt
Missing required environment variables:

- VIRUSTOTAL_API_KEY required by scanner virustotal
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
OpenAI-compatible provider, `OPENAI_API_KEY` is required.

Judge harness credentials are owned by the command you pass to `--judge`.
ClawScan does not add model-provider API keys to its own CLI flags or artifacts.

## Usage

```bash
clawscan <target> --scanner <scanner-id> [flags]
```

`<target>` is usually the path to the skill directory or skill file to scan.
Some scanners can support URL targets when their upstream scanner is a public
lookup service. In v1, `gendigital` uses this shape for ClawHub skill URLs:

```bash
clawscan https://clawhub.ai/author/skill-name \
  --scanner gendigital \
  --json
```

URL targets are recorded as `"target.kind": "url"` in the run artifact. Local
file copying for judge workspaces and `{{ target.files }}` remains path-based
and may fail clearly for URL targets.

### Flags

| Flag | Required | Repeatable | Description |
| --- | --- | --- | --- |
| `--scanner <id>` | Yes | Yes | Scanner to run. Accepted IDs are listed above. |
| `--scanner-result <id=path>` | No | Yes | Use a JSON fixture as the scanner result instead of running that scanner. The scanner must also be listed with `--scanner`. |
| `--output <path>` | No | No | Write the run artifact JSON to a file. |
| `--json` | No | No | Print the run artifact JSON to stdout. |
| `--judge <cmd>` | No | No | External judge harness command. ClawScan interpolates placeholders, runs it through `/bin/sh -c`, and records its JSON output. |

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
  --scanner skillspector \
  --scanner cisco \
  --scanner snyk \
  --scanner virustotal \
  --output ./clawscan-run.json
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

## Judge Harness

The intended judge flow is:

1. Run requested scanners.
2. Wait for all scanner results.
3. Prepare a temporary judge workspace.
4. Render any prompt referenced by `{{ prompt }}` or `{{ prompt:<path> }}`.
5. Copy any schema referenced by `{{ output_schema }}` or
   `{{ output_schema:<path> }}`.
6. Interpolate placeholders into `--judge`.
7. Run the judge command and store its JSON result alongside scanner evidence.

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
```

Run the current CLI smoke test manually:

```bash
go run ./cmd/clawscan ./README.md \
  --scanner skillspector \
  --output /tmp/clawscan-smoke.json
```

Check the prompt parity proof:

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /Users/patrickerichsen/.codex/worktrees/67c6/clawhub \
  --out /tmp/clawhub-prompt-parity-proof-go.json
```
