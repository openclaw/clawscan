---
name: clawscan-cli
description: Use when running or explaining the ClawScan CLI, including one-off agent-skill scans, benchmark runs, scanner fixtures, judge harness commands, env var validation, and interpreting clawscan-run-v1 and clawscan-benchmark-v1 artifacts.
---

# ClawScan CLI

## Overview

Use ClawScan to run one or more security scanners against agent skills, preserve
raw scanner evidence, and optionally pass the evidence to an external judge
harness. The public CLI is general-purpose; ClawHub-specific parity helpers
belong outside `cmd/clawscan`. Keep secrets in environment variables, never CLI
flags.

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
| Scan repo skills with one scanner | `clawscan --scanner skillspector` from a repo with `./skills/<name>/SKILL.md` |
| Scan repo skills with the ClawHub profile | `clawscan --profile clawhub` from a repo with `./skills/<name>/SKILL.md` |
| Scan one explicit target with a profile | `clawscan ./my-skill --profile clawhub` |
| Capture raw scanner evidence only | `clawscan ./my-skill --scanner clawscan-static` |
| Print raw JSON to stdout | Add `--json`. |
| Run all profiles from a config | `clawscan ./my-skill --config ./security/clawscan.yml` |
| Run one config profile | `clawscan ./my-skill --config ./security/clawscan.yml --profile review` |
| Install scanner dependencies | `clawscan install aig cisco skillspector` |
| List scanner catalog | `clawscan scanners` |
| Inspect one scanner | `clawscan scanners skillspector` |
| List resolved profiles | `clawscan profiles` |
| Print resolved profile YAML | `clawscan profiles -v` |
| List benchmark catalog | `clawscan benchmark list` |
| Run SkillTrustBench | `clawscan benchmark SkillTrustBench --limit 10 --scanner clawscan-static --output run.json` |
| Run ClawHub Security Signals | `clawscan benchmark clawhub-security-signals --split eval_holdout --limit 10 --scanner clawscan-static --output run.json` |
| Use stable scanner evidence | Add `--scanner-result <id=path>` for each fixture-backed scanner. |
| Add or override a judge harness | Add `--judge '<command with placeholders>'`. |
| Use host-installed scanner/judge CLIs | Add `--sandbox off` only in an already-isolated environment. |

Helpful metadata:

```bash
clawscan --help
clawscan -h
clawscan --version
clawscan scanners
clawscan profiles
clawscan benchmark list
```

Unless `--json` is passed, ClawScan writes the full artifact to
`./clawscan-results/artifact.json` by default, preserves per-scanner JSON files
in the same visible results bundle, and prints a concise key/value summary
ending in `full_results: ./clawscan-results/artifact.json`. Use
`--output <path>` to choose a different artifact path; explicit `.json` paths
keep that artifact file and write scanner JSON beside it.

## Targets, Profiles, And Config

If no target is passed with `--scanner`, `--profile`, or `--config`, ClawScan
scans child skill directories under `./skills`. If `./skills` is missing or
contains no children with `SKILL.md`, it fails with a target-discovery error.
Plain `clawscan` without `--scanner`, `--profile`, or `--config` is invalid.
Benchmark runs use `clawscan benchmark <benchmark-id>` and do not accept scan
targets.

Built-in profiles:

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | bundled Codex judge with ClawHub prompt/schema |

Profiles are loaded from embedded built-ins plus the nearest `.clawscan.yml` or
`.clawscan.yaml` discovered upward from the current directory. A project profile
with the same name shadows the built-in whole profile. `--config <path>` loads a
specific config; without `--profile`, it runs every profile in that config and
emits a `clawscan-batch-v1` artifact.

Use `clawscan profiles` to inspect the resolved built-in plus nearest local
profile catalog. Use `clawscan profiles -v` to print the merged catalog as
pasteable YAML.

CLI flags override the selected profile for one run. Passing `--scanner`
without `--profile` creates an ad hoc scanner-only run, so profile judges are
not invoked accidentally.

Minimal config:

```yaml
version: 1
sandbox:
  mode: docker
  env:
    - OPENAI_API_KEY
    - CODEX_API_KEY
profiles:
  review:
    scanners:
      - clawscan-static
    json: true
    judge:
      command: judge --out {{ output }}
```

`sandbox.env` is an allowlist of env var names to pass into the Docker runtime;
store names there, not secret values. CLI equivalents are `--sandbox`,
`--sandbox-image`, and repeatable `--sandbox-env`.

## Scanners

Use `clawscan scanners` for the registry-backed scanner catalog and
`clawscan scanners <scanner-id>` for one scanner's repository, description,
env vars, and install guidance.

Accepted scanner IDs:

```text
agentverus, aig, cisco, clawscan-static, skillspector, snyk, socket, virustotal
```

Credential rules:

| Scanner | Env vars |
| --- | --- |
| `aig` | required: `LLM_API_KEY` or `OPENAI_API_KEY`; optional local scanner config: `DEFAULT_MODEL`, `DEFAULT_BASE_URL`, `DEFAULT_MODEL_CONTEXT_WINDOW`, `LOG_LEVEL` |
| `socket` | required: `SOCKET_CLI_API_TOKEN` |
| `snyk` | required: `SNYK_TOKEN` |
| `virustotal` | required: `VIRUSTOTAL_API_KEY` |
| `skillspector` | optional provider config: `SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL`, `NVIDIA_INFERENCE_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_PROXY_ENDPOINT_URL`, `ANTHROPIC_PROXY_API_KEY` |
| `cisco` | optional upstream analyzers: `SKILL_SCANNER_LLM_*`, `SKILL_SCANNER_META_LLM_*`, `VIRUSTOTAL_API_KEY`, `AI_DEFENSE_API_KEY`, `AI_DEFENSE_API_URL` |

Artifact env fields record only `present` or `missing`; they must never contain
secret values. GenDigital/Gen Agent Trust Hub is not a built-in scanner because
there is no local CLI for ClawScan to invoke.

Dependency setup:

```bash
clawscan install aig cisco skillspector
```

`clawscan install` accepts one or more scanner IDs. It follows upstream scanner
install docs where they publish an install command, including A.I.G's
`pip install aig-skill-scan`, Cisco's `uv pip install cisco-ai-skill-scanner`, SkillSpector's
`uv tool install git+https://github.com/NVIDIA/skillspector.git`, Socket's
`npm install -g socket`, and AgentVerus'
`npm install --save-dev agentverus-scanner`. Snyk is launcher-based, so
ClawScan verifies `uvx`; built-in and simple API-backed scanners are skipped.
The `aig` adapter runs `aig-skill-scan --repo <target> --language en -o
<result.sarif.json>` and stores the SARIF 2.1.0 document as raw scanner
evidence.

Starting in ClawScan `v0.1.2`, `aig` no longer uses the legacy A.I.G Docker/API
service. Replace `AIG_MODEL` with `DEFAULT_MODEL`, `AIG_MODEL_BASE_URL` with
`DEFAULT_BASE_URL`, and `AIG_MODEL_API_KEY` with `LLM_API_KEY` or
`OPENAI_API_KEY`; `AIG_BASE_URL` and `AIG_API_KEY` are retired. The local
scanner accepts directory targets only.

For normal runs, command-backed scanners and judges run in
`ghcr.io/openclaw/clawscan-runtime:latest`. `clawscan install` is mainly for
local development or `--sandbox off` environments.

Use `--scanner-result` when a test or fixture should supply stable scanner JSON:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner-result skillspector=./fixtures/skillspector.json \
  --json
```

The scanner must still be requested with `--scanner` or via the selected
profile.

## Benchmarks

Use `clawscan benchmark list` for the registry-backed benchmark catalog.

Supported benchmarks:

```text
cuhk-zhuque/SkillTrustBench
clawhub-security-signals
```

Run SkillTrustBench with the canonical Hugging Face ID or the short alias
`SkillTrustBench`:

```bash
clawscan benchmark SkillTrustBench \
  --limit 10 \
  --scanner clawscan-static \
  --output /tmp/clawscan-benchmark.json
```

SkillTrustBench uses split `benchmark`. The first live run downloads and caches
`benchmark_full_v1.0.zip`, then extracts only the requested case directories
into temporary scan targets.

Use `--ids <path-or-url>` with SkillTrustBench to run a fixed subset from a
plain text file with one ID per line or JSONL rows with an `id` field. `--ids`
preserves source order, records `idsSource`, `idsCount`, and `idsSha256` in the
artifact, and is mutually exclusive with `--limit` and `--offset`.

ClawHub Security Signals splits: `train`, `validation`, `test`,
`eval_holdout`. `--limit 0` means run the full selected split. Use `--offset`
with `--limit` for reproducible chunks.

For `clawhub-security-signals`, `--output ./clawscan-benchmark.json` also
writes `./predictions.jsonl`. Use `--predictions-output <path>` to choose
another path. `--predictions-output` is only supported for
`clawhub-security-signals`.

Benchmark artifacts use `clawscan-benchmark-v1`. Each case embeds the normal
`clawscan-run-v1` artifact, expected verdict metadata, and evaluation status.
The summary includes case counts, scanner/judge statuses, and accuracy over
scored cases. Inspect the JSON artifact for full evidence.

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
The built-in `clawhub` profile uses this same judge mechanism with embedded
prompt and output-schema files.

## Verification

Use static scanner smokes for local proof because they do not need secrets:

```bash
go run ./cmd/clawscan ./README.md --scanner clawscan-static --output /tmp/clawscan-smoke.json
go run ./cmd/clawscan benchmark SkillTrustBench --limit 1 --scanner clawscan-static --output /tmp/clawscan-benchmark-smoke.json
go run ./cmd/clawscan --help
go test -count=1 ./...
go vet ./...
```

## Common Mistakes

- Do not pass API keys as CLI flags.
- Do not run plain `clawscan`; choose `--scanner`, `--profile`, `--config`, or
  `clawscan benchmark <benchmark-id>`.
- Do not assume `clawscan` scans `.`; no target means discover `./skills`.
- Do not expect a profile judge when passing explicit `--scanner` flags without
  `--profile`.
- Do not use benchmark flags such as `--split`, `--limit`, or `--offset`
  outside `clawscan benchmark <benchmark-id>`.
- Do not use `--config` without `--profile` for benchmark runs; all-profile
  config runs are target scans only.
- Do not assume host-installed scanner CLIs are used by default; command-backed
  scanners and judges use the Docker runtime unless `--sandbox off` is set.
- Do not add unsupported dataset names; built-ins are SkillTrustBench and
  `clawhub-security-signals`.
- Do not assume scanner failures are final policy verdicts; scanner output is
  raw evidence for comparison or judging.
