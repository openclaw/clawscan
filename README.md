# ClawScan

ClawScan is a standalone security runner for OpenClaw skills. It gives us one
small command for running multiple skill scanners, collecting their raw evidence,
and optionally passing that evidence into a judge prompt.

The first goal is reproducibility: the open source tool should be able to run the
same ClawHub ClawScan setup we run internally, while making it easier for others
to compare scanners and iterate on their own judge prompts.

## Motivation

The agent-skill scanner space is moving quickly. New scanners are appearing,
existing scanners are changing their threat models, and no single scanner should
be treated as ground truth.

ClawScan exists to make that messy comparison work boring:

- Run several scanners against the same skill with one command.
- Preserve each scanner's raw JSON evidence instead of forcing one normalized
  verdict too early.
- Compare scanner output side by side.
- Iterate on a judge prompt and output schema without rewriting scanner glue.
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
- ClawHub prompt parity proof tooling

Scanner adapters and judge execution are being filled in incrementally. Until an
adapter is implemented, its scanner result is recorded as `skipped` with a clear
error in the run artifact.

## Supported Scanners

These scanner IDs are accepted by the CLI today:

| Scanner ID | Source | Notes |
| --- | --- | --- |
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Security scanner for AI agent skills. Intended to be the main ClawHub parity scanner. |
| `snyk` | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Snyk's scanner for AI agents, MCP servers, and skills. Requires `SNYK_TOKEN`. |
| `cisco` | [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Cisco's agent skill scanner. Supports local and optional provider-backed modes upstream. |
| `virustotal` | [VirusTotal API](https://docs.virustotal.com/reference/file) | File reputation and malware telemetry. Requires `VIRUSTOTAL_API_KEY`. |
| `gendigital` | [Gen Digital Skill Scanner](https://ai.gendigital.com/skill-scanner) | Public lookup-style scanner for ClawHub skill URLs. |
| `clawhub-static` | Built in | Lightweight local static scanner for ClawHub/OpenClaw skill artifacts. |

Planned scanners should not be added to this table until the CLI accepts their
scanner ID.

## Install

From the repository root:

```bash
go install ./cmd/clawscan
```

For local development, run without installing:

```bash
go run ./cmd/clawscan ./my-skill --scanner skillspector --json
```

## Secrets

Secrets must be provided through environment variables, not CLI flags.

```bash
export VIRUSTOTAL_API_KEY=...
export SNYK_TOKEN=...
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
```

ClawScan validates required variables before starting a run. Missing variables
are grouped into one error:

```txt
Missing required environment variables:

- VIRUSTOTAL_API_KEY required by scanner virustotal
- OPENAI_API_KEY required by judge model openai/gpt-5.5
```

Run artifacts record only whether a variable was present:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Actual secret values are never written to the artifact.

## Usage

```bash
clawscan <target> --scanner <scanner-id> [flags]
```

`<target>` is the path to the skill directory or skill file to scan.

### Flags

| Flag | Required | Repeatable | Description |
| --- | --- | --- | --- |
| `--scanner <id>` | Yes | Yes | Scanner to run. Accepted IDs are listed above. |
| `--output <path>` | No | No | Write the run artifact JSON to a file. |
| `--json` | No | No | Print the run artifact JSON to stdout. |
| `--judge-prompt <path>` | With judge | No | Markdown prompt file for the judge model. |
| `--judge-schema <path>` | With judge | No | JSON Schema file the judge output must satisfy. |
| `--judge-model <provider/model>` | With judge | No | Judge model, using `openai/...` or `anthropic/...`. |
| `--judge-reasoning <level>` | No | No | Reasoning effort hint for providers that support it. |

Judge flags are all-or-nothing: if any judge flag is present, `--judge-prompt`,
`--judge-schema`, and `--judge-model` are required.

Current model providers:

- `openai/<model>` requires `OPENAI_API_KEY`
- `anthropic/<model>` requires `ANTHROPIC_API_KEY`

## Sample Commands

Run one scanner and print JSON:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --json
```

Run several scanners and save the artifact:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner cisco \
  --scanner snyk \
  --scanner virustotal \
  --output ./clawscan-run.json
```

Run scanner comparison with a judge prompt and schema:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner virustotal \
  --scanner clawhub-static \
  --judge-model openai/gpt-5.5 \
  --judge-reasoning high \
  --judge-prompt ./prompts/security-judge.md \
  --judge-schema ./schemas/security-verdict.schema.json \
  --output ./clawscan-judged.json
```

Use Anthropic as the judge provider:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge-model anthropic/claude-sonnet-4.5 \
  --judge-prompt ./judge.md \
  --judge-schema ./schema.json \
  --json
```

Run the ClawHub prompt parity proof against a local ClawHub checkout:

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /path/to/clawhub \
  --out /tmp/clawhub-prompt-parity-proof-go.json
```

The parity proof compares the Go-rendered prompt against the current ClawHub
TypeScript worker output char-for-char and records the prompt length, SHA-256,
and whether SkillSpector evidence was supplied through the runtime input path.

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
      "command": null,
      "error": "Scanner adapter not implemented in foundation slice.",
      "raw": null
    }
  },
  "judge": null
}
```

The important design choice is that scanner output remains raw evidence. The
judge prompt decides how to interpret it.

## Judge Prompt Model

The intended judge flow is:

1. Run requested scanners.
2. Wait for all scanner results.
3. Interpolate raw scanner JSON into the judge prompt.
4. Call the configured judge model.
5. Validate the judge response against `--judge-schema`.
6. Store the judge result alongside scanner evidence.

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
