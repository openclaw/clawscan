# Quickstart

## Install

From a published module:

```bash
go install github.com/openclaw/clawscan/cmd/clawscan@latest
```

From this repository:

```bash
go install ./cmd/clawscan
```

During development, run the CLI directly:

```bash
go run ./cmd/clawscan ./my-skill --scanner clawscan-static --json
```

## One-Off Scan

Scan a local skill directory with the built-in static scanner:

```bash
clawscan ./my-skill --scanner clawscan-static --json
```

Run multiple scanners and save the artifact:

```bash
clawscan ./my-skill \
  --scanner clawscan-static \
  --scanner skillspector \
  --scanner virustotal \
  --output ./clawscan-run.json
```

Some scanners support URL targets. For example, the Gen Digital adapter is a
public lookup-style scanner for ClawHub skill URLs:

```bash
clawscan https://clawhub.ai/owner/skill \
  --scanner gendigital \
  --json
```

## Environment Variables

Secrets must be set with environment variables, not CLI flags:

```bash
export VIRUSTOTAL_API_KEY=...
export SNYK_TOKEN=...
export AIG_BASE_URL=http://127.0.0.1:8088
export AIG_MODEL=gpt-4.1
export AIG_MODEL_API_KEY=...
```

ClawScan validates required env vars before starting a run and records only
whether each value was present:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Actual secret values are never written to run artifacts.

## Common Flags

| Flag | Description |
| --- | --- |
| `--scanner <id>` | Scanner to run. Repeat for multiple scanners. |
| `--scanner-result <id=path>` | Use a JSON fixture instead of running that scanner. |
| `--output <path>` | Write the run artifact JSON to a file. |
| `--json` | Print the run artifact JSON to stdout. |
| `--judge <cmd>` | Run an optional external judge harness. |
| `--benchmark <id>` | Run a supported benchmark instead of one target. |
| `--split <name>` | Benchmark split. Defaults to `eval_holdout`. |
| `--limit <n>` | Maximum benchmark rows to run. `0` means all rows. |
| `--offset <n>` | Benchmark row offset. Defaults to `0`. |

## Help Output

```bash
clawscan --help
clawscan --version
```
