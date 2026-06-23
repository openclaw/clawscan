# Scanners

ClawScan scanner adapters produce evidence. They do not become the policy engine
by themselves.

## Supported Scanner IDs

| Scanner ID | Source | Target support | Required env vars |
| --- | --- | --- | --- |
| `agentverus` | [AgentVerus](https://agentverus.ai/) | Local file or directory through `npx --yes agentverus-scanner scan <target> --json`. | None for the local scanner path. |
| `ai-infra-guard` | [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Local targets are zipped and uploaded to a self-hosted A.I.G taskapi service. URL targets are passed to `mcp_scan`. | `AIG_BASE_URL`, `AIG_MODEL`, `AIG_MODEL_API_KEY`. |
| `cisco` | [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory through `skill-scanner scan <target> --format json --output <tempfile>`. | None required by ClawScan. Configure Cisco's CLI separately. |
| `gendigital` | [Gen Digital Skill Scanner](https://ai.gendigital.com/skill-scanner) | URL targets only in v1. Local paths return a scanner-specific skipped result. | None. |
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Local file or directory. Runs with `--no-llm` by default. | None by default. Provider keys are required only when `CLAWSCAN_SKILLSPECTOR_LLM=1`. |
| `snyk` | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Local skill path through `uvx snyk-agent-scan@latest scan --json --no-bootstrap --skills <target>`. | `SNYK_TOKEN`. |
| `clawscan-static` | Built in | Local file or directory. URL targets return a skipped result. | None. |
| `virustotal` | [VirusTotal API](https://docs.virustotal.com/reference/file) | Single local file hash lookup in v1. Directories return a skipped result. | `VIRUSTOTAL_API_KEY`. |

## Static Scanner

The built-in `clawscan-static` scanner is intentionally lightweight. It scans text files
within ClawScan's target-file budget and reports deterministic findings for
simple high-signal patterns such as instruction overrides, credential
exfiltration language, pipe-to-shell snippets, and destructive shell commands.

The static scanner records evidence only. It does not emit a final verdict.

## Fixture-Backed Results

Use `--scanner-result <id=path>` when you want a stable scanner result without
calling the live scanner:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner-result skillspector=./fixtures/skillspector.json \
  --scanner virustotal \
  --scanner-result virustotal=./fixtures/virustotal.json \
  --json
```

The scanner must still be listed with `--scanner`. This keeps the run explicit
and lets ClawScan validate that prompts only reference requested scanners.

## Credential Safety

ClawScan never accepts scanner API keys as CLI flags. This avoids leaking
secrets through shell history, process lists, CI logs, and run artifacts.
