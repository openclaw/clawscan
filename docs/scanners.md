# Scanners

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

## Target kinds

Clawscan classifies each explicit target before dispatching scanners and records
the result in the artifact `target.kind` field:

| Kind | Detected when | Notes |
| --- | --- | --- |
| `skill` | default for local files and directories | Historical behavior; a directory usually holds `SKILL.md`. |
| `plugin` | directory (or manifest file) holds `openclaw.plugin.json` | OpenClaw plugin. The stable manifest `id` is recorded in `target.id`; host paths are never used as identity. |
| `url` | `http`/`https` input | API-backed and static scanners skip URLs. |

The built-in `clawscan-static` scanner analyzes `plugin` targets; scanners that
assume skill layouts return an explicit `skipped` result naming the unsupported
kind, and adapters can opt in per kind as upstream tools add plugin support. A
directory carrying both `SKILL.md` and `openclaw.plugin.json` is rejected as
ambiguous rather than guessed.

Plugin targets are never auto-discovered. Zero-target discovery still scans only
child skill directories under `./skills`; pass a plugin directory explicitly to
avoid silently scanning arbitrary package directories. Pointing Clawscan at an
`openclaw.plugin.json` file scans the surrounding plugin directory.

Plugin ids follow OpenClaw's install grammar, including `@scope/name` ids. The
manifest must parse as strict JSON in this version; JSON5-only manifests
(comments, trailing commas) are rejected with an explicit error rather than
guessed at.

## Available scanners

> **Want to add your scanner to the list?** Follow the guide in [docs/scanners.md](docs/scanners.md#adding-a-built-in-scanner-adapter)

| ID | Name | Repo | Description | Required env vars | Local dependency setup |
| --- | --- | --- | --- | --- | --- |
| `agentverus` | AgentVerus | [repo](https://github.com/agentverus/agentverus-scanner) | Local file or directory scanner invoked through agentverus-scanner. | none | `npm install --save-dev agentverus-scanner` |
| `aig` | Tencent AI-Infra-Guard | [repo](https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan) | Tencent Zhuque Lab's local directory scanner invoked through `aig-skill-scan`. Produces SARIF 2.1.0 with SkillTrustBench T01-T09 evidence. | `LLM_API_KEY` or `OPENAI_API_KEY`<br><details><summary>Optional config</summary><code>DEFAULT_MODEL</code>, <code>DEFAULT_BASE_URL</code>, <code>DEFAULT_MODEL_CONTEXT_WINDOW</code>, <code>LOG_LEVEL</code>.</details> | `pip install aig-skill-scan` |
| `cisco` | Cisco AI Defense skill-scanner | [repo](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory scanner invoked through `skill-scanner` with JSON report output. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers. | none<br><details><summary>Optional config</summary><code>SKILL_SCANNER_LLM_API_KEY</code>, <code>SKILL_SCANNER_LLM_PROVIDER</code>, <code>SKILL_SCANNER_LLM_MODEL</code>, <code>SKILL_SCANNER_LLM_BASE_URL</code>, <code>SKILL_SCANNER_LLM_USER</code>, <code>SKILL_SCANNER_LLM_API_VERSION</code>, <code>SKILL_SCANNER_LLM_FORCE_JSON_OBJECT</code>, <code>SKILL_SCANNER_META_LLM_API_KEY</code>, <code>SKILL_SCANNER_META_LLM_MODEL</code>, <code>SKILL_SCANNER_META_LLM_BASE_URL</code>, <code>SKILL_SCANNER_META_LLM_API_VERSION</code>, <code>AWS_PROFILE</code>, <code>AWS_REGION</code>, <code>GOOGLE_APPLICATION_CREDENTIALS</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>AI_DEFENSE_API_KEY</code>, <code>AI_DEFENSE_API_URL</code>.</details> | `uv pip install cisco-ai-skill-scanner` |
| `clawscan-static` | ClawScan Static | [repo](https://github.com/openclaw/clawscan) | Built-in deterministic text scanner for high-signal risky skill patterns. | none | skipped; built in |
| `skillspector` | NVIDIA SkillSpector | [repo](https://github.com/NVIDIA/skillspector) | Local file or directory scanner. Uses LLM mode when provider env vars are set; otherwise runs with `--no-llm`. | none<br><details><summary>Optional config</summary><code>SKILLSPECTOR_PROVIDER</code>, <code>SKILLSPECTOR_MODEL</code>, <code>SKILLSPECTOR_MODEL_REGISTRY</code>, <code>SKILLSPECTOR_LOG_LEVEL</code>, <code>SKILLSPECTOR_SSL_VERIFY</code>, <code>NVIDIA_INFERENCE_KEY</code>, <code>OPENAI_API_KEY</code>, <code>OPENAI_BASE_URL</code>, <code>ANTHROPIC_API_KEY</code>, <code>ANTHROPIC_PROXY_ENDPOINT_URL</code>, <code>ANTHROPIC_PROXY_API_KEY</code>, <code>ANTHROPIC_PROXY_API_VERSION</code>.</details> | `uv tool install git+https://github.com/NVIDIA/skillspector.git` |
| `snyk` | Snyk Agent Scan | [repo](https://github.com/snyk/agent-scan) | Local skill scanner invoked through `uvx snyk-agent-scan`. | `SNYK_TOKEN` | verifies `uvx` launcher |
| `socket` | Socket CLI | [repo](https://github.com/SocketDev/socket-cli) | Local file or directory scanner using Socket's public CLI full-scan path. | `SOCKET_CLI_API_TOKEN` | `npm install -g socket` |
| `virustotal` | VirusTotal API | [docs](https://docs.virustotal.com/reference/file) | API-backed single local file hash lookup. Directories return a skipped result. | `VIRUSTOTAL_API_KEY` | skipped; API-backed |

### AIG migration

Starting in `v0.1.2`, the built-in `aig` scanner uses Tencent's local
`aig-skill-scan` package instead of the legacy A.I.G Docker/API service.
Replace `AIG_MODEL` with `DEFAULT_MODEL`, `AIG_MODEL_BASE_URL` with
`DEFAULT_BASE_URL`, and `AIG_MODEL_API_KEY` with `LLM_API_KEY` (or
`OPENAI_API_KEY`). `AIG_BASE_URL` and `AIG_API_KEY` are no longer used.

The local scanner accepts directory targets only. Materialize URL or file inputs
as a skill directory before scanning them with `aig`.
