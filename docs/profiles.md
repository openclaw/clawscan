# Profiles

`--profile` runs a saved scanner and judge configuration, such as the built-in
`clawhub` profile that matches ClawHub's production scanner suite and Codex
judge harness:

```bash
clawscan ./my-skill --profile clawhub
```

The same profile accepts an explicit OpenClaw plugin directory (or its
`openclaw.plugin.json` manifest), runs both scanners, and renders the
bundled judge prompt with `packageRelease` target context.

## Config discovery

By default, ClawScan does not auto-discover `.clawscan.yml` or `.clawscan.yaml`
files from the current directory or parent directories. If your run detects a
config file that could have been loaded, ClawScan prints a notice to stderr
suggesting you use `--config <path>` or `--discover-config`.

To load a discovered config file, use one of these flags:

- `--config <path>` - Explicitly specify a config file path
- `--discover-config` - Search upward from the current directory and load the nearest `.clawscan.yml` or `.clawscan.yaml`

Mixing `--config` and `--discover-config` is an error.

```bash
clawscan ./my-skill --config ./security/clawscan.yml --profile review
clawscan ./my-skill --profile review --discover-config
```

Without either flag, ClawScan uses built-in profiles and CLI flags only. The
warning is a single stderr line and never changes JSON stdout. The
`clawscan profiles` catalog command still includes the nearest discovered
project config.

## Inspect available profiles

Inspect the resolved profile catalog, including the nearest project
`.clawscan.yml` / `.clawscan.yaml` when present:

```bash
clawscan profiles
clawscan profiles -v
```

## Available profiles

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |

## Build a custom profile with `.clawscan.yml`

Custom profiles can be created in `.clawscan.yml`.

This is useful for version controlling iterations on your profile, creating multiple profiles to run over the same skills, etc

```yaml
version: 1
profiles:
  review:
    scanners:
      - skillspector
      - snyk
    sandbox:
      env:
        - OPENAI_API_KEY
        - CODEX_API_KEY
    judge:
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```
