# Profiles

`--profile` runs a saved scanner and judge configuration, such as the built-in
`clawhub` profile that matches ClawHub's production scanner suite and Codex
judge harness:

```bash
clawscan ./my-skill --profile clawhub
```

The same profile accepts an explicit OpenClaw plugin directory (or its
`openclaw.plugin.json` manifest), runs the plugin-capable scanners in the
profile, and renders the bundled judge prompt with `packageRelease` target
context.

## Config discovery

By default, ClawScan does not auto-discover `.clawscan.yml` or `.clawscan.yaml`
files from the current directory or parent directories.

ClawScan never loads a config file it was not explicitly pointed at. A
`.clawscan.yml` can define user-defined scanners whose commands execute with
your credentials in the environment, so silently loading one from the current
directory or a parent (for example, from inside a repository you are scanning)
would let an untrusted target execute commands. Pass `--config <path>` or opt in
with `--discover-config`.

To load a discovered config file, use one of these flags:

- `--config <path>` - Explicitly specify a config file path
- `--discover-config` - Search upward from the current directory and load the nearest `.clawscan.yml` or `.clawscan.yaml`

Mixing `--config` and `--discover-config` is an error. `--discover-config`
also requires `--profile`: without a profile the run would record the
discovered file as its config source while applying none of its settings.
Use `--config <path>` without `--profile` to run every profile in a config.

```bash
clawscan ./my-skill --config ./security/clawscan.yml --profile review
clawscan ./my-skill --profile review --discover-config
```

Without either flag, ClawScan uses built-in profiles and CLI flags only. The
`clawscan profiles` catalog command lists built-in profiles only.

## Inspect available profiles

Inspect the built-in profile catalog:

```bash
clawscan profiles
clawscan profiles -v
```

## Available profiles

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | skills: `skillspector`, `aig`; plugins: `aig-mcp` | Evidence-only Codex `gpt-6.1-sol` verdict from scanner results (no artifact copy; file, shell, web and code-execution tools disabled), then an evidence-only Codex `gpt-6-luna` low-effort overview |
| `clawhub-template` | `aig-mcp` only, entire shipped Template | Same existing evidence-only verdict judge and optional overview; see [Template contract](template-audit.md) |
| `clawhub-aig` | `skillspector`, `aig` | Same judge and overview as `clawhub` |
| `openclaw-install-policy` | `skillspector` | none |

Profiles can set `pluginScanners` to replace `scanners` for OpenClaw plugin
targets. The built-in `clawhub` profile uses it so a plugin is audited as one
artifact by `aig-mcp` alone: no skill scanner runs or is recorded for it, and
its SARIF is the only scanner evidence in the judge workspace. Skill targets keep the `scanners`
list unchanged. An explicit `--scanner` replaces both lists for that run.
`aig-mcp` uses the A.I.G `DEFAULT_MODEL`/`DEFAULT_BASE_URL` defaults below but
calls Chat Completions without the patched Responses transport, so
`REASONING_EFFORT` and the Standard-tier guarantees do not apply to it.

The two ClawHub profiles explicitly configure the OpenAI scanner lanes with
`scannerEnvDefaults`: SkillSpector uses `SKILLSPECTOR_PROVIDER=openai`,
`SKILLSPECTOR_MODEL=gpt-6.1-sol`, and `SKILLSPECTOR_REASONING_EFFORT=medium`;
A.I.G uses `DEFAULT_MODEL=gpt-6.1-sol` and `REASONING_EFFORT=medium` with OpenAI
credentials. The verdict comes from an evidence-only Codex run (`gpt-6.1-sol`,
high reasoning) that sees scanner results only: no artifact copy, no file,
shell or web tools. A separate evidence-only Codex overview step (`gpt-6-luna`,
low reasoning, Standard service) writes the readable summary and never changes
the verdict. Credentials stay in the environment. See
[judge harness](judge.md#clawhub-judge); the Decisions API judge remains
available through `--judge`.

Explicit model/provider/effort environment overrides win. A different
SkillSpector provider retains its own model defaults. A.I.G with a dedicated
`LLM_API_KEY` retains its provider defaults unless `DEFAULT_BASE_URL` explicitly
selects `https://api.openai.com/v1`; third-party endpoints are never redirected.
An explicit alternative model does not inherit the profile's Sol effort.
Generic `--scanner` runs and project profiles without `scannerEnvDefaults` keep
their existing provider choices. The supported defaults are only the five model
control names above, not arbitrary environment variables or credentials.

Use the runtime image built from the same source revision: its pinned NVIDIA
SkillSpector and Tencent Zhuque Lab A.I.G integrations include narrow Responses
API compatibility patches. Sol tool calls are not supported on Chat Completions;
changing only the model environment or reusing the old 0.2.0 runtime is insufficient.
See [scanner runtime compatibility](scanner-runtime.md).

## Build a custom profile with `.clawscan.yml`

Custom profiles can be created in `.clawscan.yml`.

This is useful for version controlling iterations on your profile, creating multiple profiles to run over the same skills, etc

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/openclaw/clawscan/main/schemas/clawscan.schema.json

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
      mounts:
        - /opt/scanner-rules
        - path: /var/cache/clawscan
          write: true
    judge:
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```

The schema gives editors completion and catches misspelled fields, invalid
types, unsupported values, and malformed gate rules before a scan starts.
ClawScan still validates the file when it loads so correctness does not depend
on editor support.

Sandbox mounts must use existing absolute host paths. A string mount is
read-only; set `write: true` only for a directory the scanner genuinely needs
to modify. The CLI equivalents are repeatable `--sandbox-mount /path` and
`--sandbox-mount /path:rw`. Paths containing commas or quotation marks are
supported; quote the complete argument for your shell, for example
`--sandbox-mount '/opt/scanner rules, v2'`.
