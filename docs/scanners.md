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
| `socket` | [Socket CLI](https://github.com/SocketDev/socket-cli) | Local file or directory through `npx --yes socket scan create --json <target>`. This uses Socket's public full-scan CLI path and does not claim private skills.sh backend parity. | `SOCKET_TOKEN`. |
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

## Adding A Built-In Scanner Adapter

Built-in scanners are registered through `internal/runner.ScannerRegistry`.
Avoid one-off switches in the CLI. The registry keeps scanner IDs, env
requirements, and dispatch behavior in one place so help output, profiles, and
tests can reason about the same public scanner surface.

### Registry Contract

A built-in adapter must provide:

- a stable public scanner ID
- any required environment variables through `Requirements`
- a `Run` implementation that returns a `ScannerResult`

Register the adapter in `defaultScannerAdapters()` in
`internal/runner/scanner_registry.go`. Public scanner IDs are part of the CLI
surface, so choose a lowercase, hyphenated ID that you are willing to document.

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

At minimum, a result should make these facts clear:

- scanner status: completed, skipped, or errored
- command or API path used, without secrets
- started and completed timestamps
- raw JSON evidence or a clear skipped/error explanation

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
scanner ID list matches the docs.
