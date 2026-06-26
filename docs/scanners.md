# Scanners

ClawScan scanner adapters produce evidence. They do not become the policy engine
by themselves.

## Supported Scanner IDs

Use `clawscan scanners` for the compact catalog, or
`clawscan scanners <scanner-id>` for the registry-backed detail view with the
upstream link, description, env vars, and install guidance.

| Scanner ID | Source | Target support | Required env vars |
| --- | --- | --- | --- |
| `agentverus` | [AgentVerus](https://github.com/agentverus/agentverus-scanner) | Local file or directory through `npx --yes agentverus-scanner scan <target> --json`. | None for the local scanner path. |
| `aig` | [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Local file or directory uploaded as a source archive, or remote URL, through a running A.I.G task API service using `mcp_scan`. Default service URL is `http://localhost:8088`. | None required by ClawScan. |
| `cisco` | [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory through `skill-scanner scan <target> --format json --output <tempfile>`. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers. | None required by ClawScan. |
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Local file or directory. Uses SkillSpector LLM mode when provider env vars are set; otherwise passes `--no-llm`. | None required by ClawScan. |
| `snyk` | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Local skill path through `uvx snyk-agent-scan@latest scan --json --no-bootstrap --skills <target>`. | `SNYK_TOKEN`. |
| `socket` | [Socket CLI](https://github.com/SocketDev/socket-cli) | Local file or directory through `npx --yes socket scan create --json <target>`. This uses Socket's public full-scan CLI path and does not claim private skills.sh backend parity. | `SOCKET_CLI_API_TOKEN`. |
| `clawscan-static` | Built in | Local file or directory. URL targets return a skipped result. | None. |
| `virustotal` | [VirusTotal API](https://docs.virustotal.com/reference/file) | Single local file hash lookup in v1. Directories return a skipped result. | `VIRUSTOTAL_API_KEY`. |

## Model-Backed Scanner Env Vars

Tencent AI-Infra-Guard runs as a Docker/API-backed service. `AIG_BASE_URL`
defaults to `http://localhost:8088`; point it at a local or private-network
service only. Upstream currently lacks built-in authentication, so do not expose
the A.I.G service on public networks. Optional ClawScan env vars are
`AIG_BASE_URL`, `AIG_API_KEY`, `AIG_MODEL`, `AIG_MODEL_API_KEY`,
`AIG_MODEL_BASE_URL`, `AIG_USERNAME`, `AIG_SCAN_LANGUAGE`, `AIG_SCAN_PROMPT`,
`AIG_SCAN_THREAD_COUNT`, `AIG_POLL_INTERVAL_MS`, and
`AIG_POLL_MAX_ATTEMPTS`. Upstream model fields are optional and can fall back
to the A.I.G service defaults.

SkillSpector uses LLM mode when provider credentials are present; otherwise
ClawScan passes `--no-llm`. Recognized optional env vars are:
`SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL`,
`SKILLSPECTOR_MODEL_REGISTRY`, `SKILLSPECTOR_LOG_LEVEL`,
`SKILLSPECTOR_SSL_VERIFY`, `NVIDIA_INFERENCE_KEY`, `OPENAI_API_KEY`,
`OPENAI_BASE_URL`, `ANTHROPIC_API_KEY`,
`ANTHROPIC_PROXY_ENDPOINT_URL`, `ANTHROPIC_PROXY_API_KEY`, and
`ANTHROPIC_PROXY_API_VERSION`.

Cisco's adapter enables upstream optional analyzers when their env vars are
present: LLM analyzer via `SKILL_SCANNER_LLM_API_KEY`,
`SKILL_SCANNER_LLM_PROVIDER`, `SKILL_SCANNER_LLM_MODEL`,
`SKILL_SCANNER_LLM_BASE_URL`, `SKILL_SCANNER_LLM_USER`,
`SKILL_SCANNER_LLM_API_VERSION`, `SKILL_SCANNER_LLM_FORCE_JSON_OBJECT`,
`AWS_PROFILE`, `AWS_REGION`, or `GOOGLE_APPLICATION_CREDENTIALS`;
meta-analyzer via `SKILL_SCANNER_META_LLM_API_KEY`,
`SKILL_SCANNER_META_LLM_MODEL`, `SKILL_SCANNER_META_LLM_BASE_URL`, or
`SKILL_SCANNER_META_LLM_API_VERSION`; VirusTotal via `VIRUSTOTAL_API_KEY`;
and Cisco AI Defense via `AI_DEFENSE_API_KEY` or `AI_DEFENSE_API_URL`.

## Installing Scanner Dependencies

Use `clawscan install <scanner-id> [scanner-id ...]` to install or verify the
local tools used by built-in scanner adapters without running a scan:

```bash
clawscan install cisco skillspector
```

The command is registry-driven and runs requested plans in order. It exits
nonzero if any requested install fails.

| Scanner ID | Install behavior |
| --- | --- |
| `agentverus` | Runs the upstream install command `npm install --save-dev agentverus-scanner`, then verifies `npx agentverus --help`. This is a project-local npm dev dependency install. |
| `aig` | No local scanner CLI is installed. Run the A.I.G Docker/API service separately on localhost or a private network; ClawScan only talks to the service API. |
| `cisco` | Runs the upstream install command `uv pip install cisco-ai-skill-scanner`, then verifies `skill-scanner --help`. |
| `clawscan-static` | Skips local install because the scanner is built into ClawScan. |
| `skillspector` | Runs the upstream install command `uv tool install git+https://github.com/NVIDIA/skillspector.git`, then verifies `skillspector --help`. |
| `snyk` | Verifies `uvx`, because scans run through `uvx snyk-agent-scan@latest ...`. |
| `socket` | Runs the upstream install command `npm install -g socket`, then verifies `socket --help`. |
| `virustotal` | Skips local install. Configure `VIRUSTOTAL_API_KEY` at scan time. |

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

## Adding A Built-In Scanner Adapter

Built-in scanners are registered through `internal/runner.ScannerRegistry`.
Avoid one-off switches in the CLI. The registry keeps scanner IDs, env
requirements, and dispatch behavior in one place so help output, profiles, and
tests can reason about the same public scanner surface.

### Registry Contract

A built-in adapter must provide:

- a stable public scanner ID
- any required environment variables through `Requirements`
- catalog metadata through `Info`, including display name, repository URL,
  description, env var lists, and install guidance
- install metadata through `InstallPlan`
- a `Run` implementation that returns a `ScannerResult`

Register the adapter in `defaultScannerAdapters()` in
`internal/runner/scanner_registry.go`. Keep `InstallPlan` focused on lifecycle
behavior; put user-facing repository and description fields in `Info`. Public
scanner IDs are part of the CLI surface, so choose a lowercase, hyphenated ID
that you are willing to document.

### Environment Requirements

Declare required credentials before the scanner runs. Use
`staticEnvRequirements` when the scanner always needs the same env vars, or a
custom requirements function when credentials are conditional.

Do not add API-key flags. Credentials belong in environment variables, and run
artifacts should record only whether those variables were `present` or
`missing`.

### Raw Evidence

Scanner adapters should preserve the upstream JSON evidence whenever possible.
If a scanner skips a target or fails before producing upstream JSON, return a
small wrapper that explains the skipped or error state. Do not flatten scanner
output into ClawScan policy verdicts inside the adapter.

When a run writes an artifact bundle, ClawScan also writes each scanner's raw
JSON to a per-scanner file and records the relative path in
`ScannerResult.outputPath`. File-emitting adapters such as Cisco and
SkillSpector should return the exact JSON bytes they read from the upstream
report file so the preserved report matches the embedded `raw` evidence.

At minimum, a result should make these facts clear:

- scanner status: completed, skipped, or errored
- command or API path used, without secrets
- started and completed timestamps
- raw JSON evidence, plus an artifact `outputPath` when that evidence is
  written to the results bundle
- a clear skipped/error explanation when raw evidence is unavailable

### Tests And Fixtures

Add fixture-backed tests for adapter behavior. Prefer stub commands, fake HTTP
clients, or `--scanner-result` fixtures over live service calls. Live smoke
tests are useful only when credentials are already available and the output can
be safely redacted.

Update the registry tests when the set of built-in IDs changes, and add focused
tests for env validation, target handling, raw evidence capture, skipped states,
and error redaction.

### Docs And Help Updates

When adding or removing a built-in scanner, update:

- `docs/scanners.md`
- `README.md`
- `docs/quickstart.md` if profile examples change
- public help tests in `cmd/clawscan`
- profile fixtures or docs if built-in profiles change

Run `go run ./cmd/clawscan --help` before handoff and confirm the accepted
scanner ID list matches the docs. Also run `go run ./cmd/clawscan scanners`
and `go run ./cmd/clawscan scanners <scanner-id>` to confirm catalog metadata
is visible from the CLI.
