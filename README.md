# ClawScan 📡

ClawScan is a composable security scanning harness for agent skills.

Run a suite of skill security scanners, pass the results to a judge harness, and compare against multiple skill security benchmarks.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/ci.yml?query=branch%3Amain)
[![Release](https://img.shields.io/badge/Release-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/badge/latest%20release-unreleased-lightgrey)](https://github.com/openclaw/clawscan/releases)


## Quick Start

Install ClawScan:

```bash
brew install openclaw/tap/clawscan
```

Install [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) and
[Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner):

```bash
clawscan install skillspector cisco
```

Run NVIDIA SkillSpector and Cisco Skill Scanner against a local `skills/` folder:

```bash
clawscan --scanner skillspector --scanner cisco
```

## Scan a known malicious skill

This example scans Trail of Bits' [`csv-summarizer`](https://github.com/trailofbits/overtly-malicious-skills/tree/4ffbf9461ef0505f9ce76a0d3694a18ec33ea531/skills/csv-summarizer) skill, which claims to summarize a CSV file but also prints every environment variable when run.

```bash
git clone https://github.com/trailofbits/overtly-malicious-skills.git /tmp/overtly-malicious-skills
cd /tmp/overtly-malicious-skills
git checkout 4ffbf9461ef0505f9ce76a0d3694a18ec33ea531
clawscan skills/csv-summarizer \
  --scanner skillspector \
  --scanner cisco \
  --output /tmp/clawscan-csv-summarizer.json
```

Sample findings:

```txt
targets: 1
scanner_completed: 2
scanner_failed: 0
scanner_skipped: 0
issues_found: 2
errors: 0
full_results: /tmp/clawscan-csv-summarizer.json
```

The results bundle keeps the top-level artifact plus per-scanner JSON reports.

<details>
<summary>Artifact excerpt</summary>

```json
{
  "schemaVersion": "clawscan-run-v1",
  "target": "skills/csv-summarizer",
  "scanners": {
    "cisco": {
      "status": "completed",
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/cisco.json",
      "isSafe": true,
      "maxSeverity": "SAFE",
      "findingsCount": 0
    },
    "skillspector": {
      "status": "completed",
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/skillspector.json",
      "severity": "MEDIUM",
      "score": 31,
      "recommendation": "CAUTION",
      "issues": [
        {
          "id": "LP3",
          "severity": "MEDIUM",
          "file": "SKILL.md"
        },
        {
          "id": "E2",
          "severity": "HIGH",
          "file": "scripts/summarize.py"
        }
      ]
    }
  }
}
```

</details>


## Motivation

Agent-skill security is new and fast-moving, with researchers and companies
exploring many promising scanners, datasets, and judge harnesses. In our
[ClawHub Security Signals paper](https://arxiv.org/html/2606.01494v1), we found
that combining multiple scanners with a configurable judge works better than
relying on any single scanner.

ClawScan turns that approach into a repeatable CLI. It includes a built-in `clawhub` profile, a saved scanner-and-judge configuration that matches what ClawHub runs in production, so researchers can reproduce results, test improvements, and help improve detection against the weekly refreshed ClawHub security-signals dataset.

## Commands

| Command family | Use |
| --- | --- |
| `clawscan <target> --scanner <id>` | Run one or more scanners against an explicit target. Omit `<target>` to scan child skill directories under `./skills`. |
| `clawscan scanners [list\|<scanner-id>]` | Discover supported scanner IDs, required env vars, upstream links, descriptions, and install guidance. |
| `clawscan profiles [-v]` | Inspect built-in plus nearest project-local profiles; `-v` prints the resolved profile catalog as YAML. |
| `clawscan benchmark [list\|<benchmark-id>]` | Discover or run supported benchmarks through a selected scanner/profile/judge setup. |
| `clawscan install <scanner-id> [...]` | Install or verify local scanner dependencies where ClawScan has registry-backed install plans. |

## Scanners

`--scanner` selects a scanner adapter to run, writes its raw JSON evidence into
the results artifact, and can be repeated to compare multiple scanners in one
run:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner cisco
```

Discover the scanner catalog from the CLI:

```bash
clawscan scanners
clawscan scanners skillspector
```

### Available scanners

> **Want to add your scanner to the list?** Follow the guide in [docs/scanners.md](docs/scanners.md#adding-a-built-in-scanner-adapter)

| ID | Name | Repo | Description | Required env vars | Local dependency setup |
| --- | --- | --- | --- | --- | --- |
| `agentverus` | AgentVerus | [repo](https://github.com/agentverus/agentverus-scanner) | Local file or directory scanner invoked through agentverus-scanner. | none | `npm install --save-dev agentverus-scanner` |
| `aig` | Tencent AI-Infra-Guard | [repo](https://github.com/Tencent/AI-Infra-Guard) | API-backed MCP Server & Agent Skills scan through a running local or private A.I.G service. Upstream defaults to `http://localhost:8088` and currently lacks built-in authentication, so do not expose it on public networks. | none<br><details><summary>Optional config</summary><code>AIG_BASE_URL</code>, <code>AIG_API_KEY</code>, <code>AIG_MODEL</code>, <code>AIG_MODEL_API_KEY</code>, <code>AIG_MODEL_BASE_URL</code>, <code>AIG_USERNAME</code>, <code>AIG_SCAN_LANGUAGE</code>, <code>AIG_SCAN_PROMPT</code>, <code>AIG_SCAN_THREAD_COUNT</code>, <code>AIG_POLL_INTERVAL_MS</code>, <code>AIG_POLL_MAX_ATTEMPTS</code>.<br><br><code>AIG_BASE_URL</code> defaults to <code>http://localhost:8088</code>; upstream model config is optional and can fall back to the A.I.G service defaults.</details> | run the A.I.G Docker/API service separately |
| `cisco` | Cisco AI Defense skill-scanner | [repo](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory scanner invoked through `skill-scanner` with JSON report output. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers. | none<br><details><summary>Optional config</summary><code>SKILL_SCANNER_LLM_API_KEY</code>, <code>SKILL_SCANNER_LLM_PROVIDER</code>, <code>SKILL_SCANNER_LLM_MODEL</code>, <code>SKILL_SCANNER_LLM_BASE_URL</code>, <code>SKILL_SCANNER_LLM_USER</code>, <code>SKILL_SCANNER_LLM_API_VERSION</code>, <code>SKILL_SCANNER_LLM_FORCE_JSON_OBJECT</code>, <code>SKILL_SCANNER_META_LLM_API_KEY</code>, <code>SKILL_SCANNER_META_LLM_MODEL</code>, <code>SKILL_SCANNER_META_LLM_BASE_URL</code>, <code>SKILL_SCANNER_META_LLM_API_VERSION</code>, <code>AWS_PROFILE</code>, <code>AWS_REGION</code>, <code>GOOGLE_APPLICATION_CREDENTIALS</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>AI_DEFENSE_API_KEY</code>, <code>AI_DEFENSE_API_URL</code>.</details> | `uv pip install cisco-ai-skill-scanner` |
| `clawscan-static` | ClawScan Static | [repo](https://github.com/openclaw/clawscan) | Built-in deterministic text scanner for high-signal risky skill patterns. | none | skipped; built in |
| `skillspector` | NVIDIA SkillSpector | [repo](https://github.com/NVIDIA/skillspector) | Local file or directory scanner. Uses LLM mode when provider env vars are set; otherwise runs with `--no-llm`. | none<br><details><summary>Optional config</summary><code>SKILLSPECTOR_PROVIDER</code>, <code>SKILLSPECTOR_MODEL</code>, <code>SKILLSPECTOR_MODEL_REGISTRY</code>, <code>SKILLSPECTOR_LOG_LEVEL</code>, <code>SKILLSPECTOR_SSL_VERIFY</code>, <code>NVIDIA_INFERENCE_KEY</code>, <code>OPENAI_API_KEY</code>, <code>OPENAI_BASE_URL</code>, <code>ANTHROPIC_API_KEY</code>, <code>ANTHROPIC_PROXY_ENDPOINT_URL</code>, <code>ANTHROPIC_PROXY_API_KEY</code>, <code>ANTHROPIC_PROXY_API_VERSION</code>.</details> | `uv tool install git+https://github.com/NVIDIA/skillspector.git` |
| `snyk` | Snyk Agent Scan | [repo](https://github.com/snyk/agent-scan) | Local skill scanner invoked through `uvx snyk-agent-scan`. | `SNYK_TOKEN` | verifies `uvx` launcher |
| `socket` | Socket CLI | [repo](https://github.com/SocketDev/socket-cli) | Local file or directory scanner using Socket's public CLI full-scan path. | `SOCKET_CLI_API_TOKEN` | `npm install -g socket` |
| `virustotal` | VirusTotal API | [docs](https://docs.virustotal.com/reference/file) | API-backed single local file hash lookup. Directories return a skipped result. | `VIRUSTOTAL_API_KEY` | skipped; API-backed |

## Judge Harness

`--judge` hands scanner evidence to an external agent command so it can inspect
the skill, do its own research in the scan workspace, and write a final JSON
verdict:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge 'codex exec --cd {{ workspace }} --output-last-message {{ output }} - < {{ prompt:./prompt.md }}'
```

Supported `--judge` placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary directory containing the copied skill, scanner JSON, and metadata. |
| `{{ prompt }}` | Render `./prompt.md` and pass the rendered prompt file path. |
| `{{ prompt:<path> }}` | Render a specific prompt template and pass that file path. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and pass that file path. |
| `{{ output_schema:<path> }}` | Copy a specific schema file and pass that file path. |
| `{{ output }}` | File path where the judge should write its final JSON object. |

## Profiles

`--profile` runs a saved scanner and judge configuration, such as the built-in
`clawhub` profile that matches ClawHub's production scanner suite and Codex
judge harness:

```bash
clawscan ./my-skill --profile clawhub
```

Inspect the resolved profile catalog, including the nearest project
`.clawscan.yml` / `.clawscan.yaml` when present:

```bash
clawscan profiles
clawscan profiles -v
```

### Available profiles

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |
| `skills-sh` | `socket`, `snyk` (Gen Agent Trust Hub also runs on skills.sh but does not offer a CLI) | none |




### Build a custom profile with `.clawscan.yml`

Custom profiles can be created in `.clawscan.yml`.

This is useful for version controlling iterations on your profile, creating multiple profiles to run over the same skills, etc

```yaml
version: 1
profiles:
  review:
    scanners:
      - skillspector
      - snyk
    judge:
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```

## Benchmarks

`clawscan benchmark <benchmark-id>` runs a supported benchmark through the
selected scanners and optional judge harness:

```bash
clawscan benchmark list

clawscan benchmark SkillTrustBench \
  --profile clawhub \
  --output ./artifacts/skilltrustbench-clawhub.json
```

### Available benchmarks

| Benchmark | ID | Source |
| --- | --- | --- |
| ClawHub Security Signals | `clawhub-security-signals` | [Hugging Face](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) |
| SkillTrustBench | `SkillTrustBench` | [Hugging Face](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench) |

### Submitting a patch to the `clawhub` profile

If you are a security researcher who found malicious skills live on ClawHub and
want to improve the production scanner so it catches them, use GitHub private
vulnerability reporting for the sensitive details and open a PR containing only
a candidate `proposals/<GHSA-ID>/clawscan.yml` config. For a guided walkthrough,
ask Codex:

```text
Use $report-clawhub-malicious-skill to walk me through reporting a malicious ClawHub skill.
```

### ClawHub Profile Benchmark

<!-- clawscan-benchmark:clawhub:start -->
Profile: `clawhub`
Benchmark: pending maintainer `SkillTrustBench Profile Gate` run.
Artifact: uploaded by the workflow as `skilltrustbench-candidate`.
<!-- clawscan-benchmark:clawhub:end -->

## Roadmap

- [ ] Command-backed custom scanner adapters, so teams can add their own scanner
  commands through a documented adapter contract once the built-in scanner
  boundary has settled.
- [ ] Reusable GitHub Action or workflow for CI. The goal is a copy-pasteable way
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
