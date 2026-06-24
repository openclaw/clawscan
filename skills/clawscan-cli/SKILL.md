---
name: clawscan-cli
description: Use when running or explaining the ClawScan CLI, including one-off agent-skill scans, OpenClaw benchmark runs, scanner fixtures, judge harness commands, env var validation, or interpreting clawscan-run-v1 and clawscan-benchmark-v1 artifacts.
---

# ClawScan CLI

## Overview

Use ClawScan to run one or more security scanners against agent skills, preserve
raw scanner evidence, and optionally pass the evidence to an external judge
harness. Keep secrets in environment variables, never CLI flags.

## Command Surface

Run from the repo root during development:

```bash
go run ./cmd/clawscan <target> --scanner <scanner-id> [flags]
```

Use the installed binary when available:

```bash
clawscan <target> --scanner <scanner-id> [flags]
```

Choose the run mode:

| Need | Shape |
| --- | --- |
| Scan one skill path | `clawscan ./my-skill --scanner clawscan-static --json` |
| Scan one URL | `clawscan https://clawhub.ai/owner/skill --scanner gendigital --json` |
| Run the default benchmark | `clawscan --benchmark --limit 10 --scanner clawscan-static --output run.json` |
| Run the OpenClaw benchmark | `clawscan --benchmark OpenClaw/clawhub-security-signals --split eval_holdout --limit 10 --scanner clawscan-static --output run.json` |
| Use stable scanner evidence | Add `--scanner-result <id=path>` for each fixture-backed scanner. |
| Add a judge harness | Add `--judge '<command with placeholders>'`. |

## Scanners

Accepted scanner IDs:

```text
agentverus, ai-infra-guard, cisco, clawscan-static, gendigital, skillspector, snyk, socket, virustotal
```

Credential rules:

| Scanner | Required env vars |
| --- | --- |
| `ai-infra-guard` | `AIG_BASE_URL`, `AIG_MODEL`, `AIG_MODEL_API_KEY` |
| `socket` | `SOCKET_TOKEN` |
| `snyk` | `SNYK_TOKEN` |
| `virustotal` | `VIRUSTOTAL_API_KEY` |
| `skillspector` | none by default; with `CLAWSCAN_SKILLSPECTOR_LLM=1`, set the provider key |

Artifact env fields record only `present` or `missing`; they must never contain
secret values.

## Benchmarks

Supported benchmarks:

```text
cuhk-zhuque/SkillTrustBench
OpenClaw/clawhub-security-signals
```

SkillTrustBench is the default benchmark. Use either `--benchmark` with no
value or the alias `--benchmark SkillTrustBench`:

```bash
clawscan \
  --benchmark \
  --limit 10 \
  --scanner clawscan-static \
  --output /tmp/clawscan-benchmark.json
```

SkillTrustBench uses split `benchmark`. The first live run downloads and caches
`benchmark_full_v1.0.zip`, then extracts only the requested case directories
into temporary scan targets.

OpenClaw splits: `train`, `validation`, `test`, `eval_holdout`. `--limit 0`
means run the full selected split. Use `--offset` with `--limit` for
reproducible chunks.

## Judge Harness

`--judge` runs through the platform shell and must produce a JSON object on
stdout or at `{{ output }}`.

Important placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary judge workspace with copied target files, scanner JSON, and metadata. |
| `{{ prompt }}` / `{{ prompt:path }}` | Render prompt template and interpolate the rendered prompt path. |
| `{{ output_schema }}` / `{{ output_schema:path }}` | Copy schema and interpolate the copied schema path. |
| `{{ output }}` | Path where the judge should write final JSON. |

Prompt files can reference requested scanner JSON:

````md
```json
{{ scanners.skillspector }}
```
````

If a prompt references an unrequested scanner, ClawScan should fail clearly.

## Verification

Use static scanner smokes for local proof because they do not need secrets:

```bash
go run ./cmd/clawscan ./README.md --scanner clawscan-static --output /tmp/clawscan-smoke.json
go run ./cmd/clawscan --benchmark --limit 1 --scanner clawscan-static --output /tmp/clawscan-benchmark-smoke.json
go test ./...
go vet ./...
```

## Common Mistakes

- Do not pass API keys as CLI flags.
- Do not use benchmark flags such as `--split`, `--limit`, or `--offset`
  without `--benchmark`.
- Do not add unsupported dataset names; built-ins are SkillTrustBench and
  `OpenClaw/clawhub-security-signals`.
- Do not assume scanner failures are final policy verdicts; scanner output is
  raw evidence for comparison or judging.
