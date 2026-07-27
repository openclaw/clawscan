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

## Profile scanner configuration

A trusted config can mix built-in scanner IDs with user-defined command
scanners. The config schema uses the existing `profiles.<name>.scanners` list:

```yaml
version: 1

profiles:
  review:
    scanners:
      - id: skillspector
        gate:
          rules:
            - id: do-not-install
              path: risk_assessment.recommendation
              equals: DO_NOT_INSTALL
              action: block
            - id: critical-finding
              path: filtered_findings[].severity
              equals: CRITICAL
              action: block
      - id: clawscan-static
        gate:
          rules:
            - id: any-finding
              path: findings[]
              exists: true
              action: warn
      - id: my-scanner
        command: my-scanner --json {{target}}
        env:
          - MY_SCANNER_MODE
        secretEnv:
          - MY_SCANNER_TOKEN
        targets:
          - skill
          - plugin
        gate:
          rules:
            - id: high-risk
              path: result.risk
              equals: high
              action: warn
          blockOnExitCode: nonzero
```

String entries select built-in scanners without gate policy. An object with a
registered built-in `id` and no `command` selects that built-in and can attach
gate rules. The rules inspect its existing JSON output; the scanner does not
need to implement ClawScan-specific policy or change its exit codes.

An object with a `command` defines a user-provided scanner for that
config-backed run. The same JSON rules work for built-in and command scanners:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Scanner ID using lowercase letters, digits, `_`, and `-`, starting with a letter or digit, at most 64 characters. It must not match a built-in scanner ID. |
| `command` | yes | Shell command to execute. Unquoted `{{target}}` is replaced with the safely passed resolved target; do not wrap the placeholder in shell quotes. |
| `env` | no | Required non-secret environment variable names passed to the scanner. Their values are not automatically redacted from scanner error text. |
| `secretEnv` | no | Required secret environment variable names passed to the scanner. Their values are redacted from scanner error text regardless of how the names are spelled. |
| `targets` | no | Supported target kinds: `skill`, `plugin`, and/or `url`. Defaults to `skill` and `url`. |
| `gate` | no | JSON and/or exit-code policy applied after the scanner completes. |

### JSON gate rules

`gate.rules` evaluates the scanner's raw JSON without rewriting it. Every rule
has:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable name reported in `gateRules`; IDs must be unique within one scanner gate. |
| `path` | yes | One path or an ordered list of aliases. Paths use dotted object fields, with `[]` after a field to traverse every array item. Separate alternative field names with the pipe character. Array indexes and other expression syntax are not supported. |
| `action` | yes | `warn` or `block`. |
| `equals` | one condition | Matches a string, number, or boolean exactly. String comparison is case-sensitive. |
| `exists` | one condition | Must be `true`; matches when the path resolves to at least one value. |
| `normalize` | no | `identifier` makes string `equals` matching case-insensitive and treats spaces and hyphens like underscores. It cannot be used with numbers, booleans, or `exists`. |
| `fallback` | no | `root` makes the first path whose root field exists authoritative, even when a nested field is missing. Use this when a preferred filtered collection must override legacy raw collections. |

Specify exactly one of `equals` or `exists: true`. A rule fires at most once,
even when several paths or array items match. The fired artifact records the
path that matched. A path list is an ordered fallback: ClawScan evaluates the
first path with a non-empty value and ignores later aliases, whether or not its
value matches. Empty strings and `null` fall through to the next alias. An
explicitly empty traversed array remains authoritative, letting a preferred
filtered result override legacy raw-result fields. Missing paths, empty arrays,
and type mismatches do not fire. Within one path segment, `|` alternatives are
resolved separately for each object, using the first present field; if that
field is empty, the rule can still fall through to the next path. For
`fallback: root`, a present root field prevents later path aliases from being
consulted. For example, `findings[].severity|risk_severity` checks `severity`
and then `risk_severity` on each finding. An immutable third-party scanner can
be gated without a wrapper:

```yaml
scanners:
  - id: third-party
    command: third-party scan --json {{target}}
    gate:
      rules:
        - id: critical-risk
          path:
            - result.risk
            - result.risk_level
          equals: critical
          normalize: identifier
          action: block
        - id: any-policy-violation
          path: result.violations[]
          exists: true
          action: warn
```

### Exit-code rules

Each exit-code rule accepts one integer from 0 through 124, a list such as
`[1, 2, 3]`, or the string `nonzero`. The block and warning rules may not
claim the same exit code. Exit codes 125 and above are reserved for shell,
container-runtime, and signal failures, so ClawScan does not treat them as
scanner verdicts. For example:

```yaml
gate:
  blockOnExitCode: [2, 3]
  warnOnExitCode: 1
```

JSON and exit-code rules can be combined on the same scanner. A gate-eligible
process exit code is preserved alongside raw JSON, and all fired rules
participate in the same strongest-action decision.

After every selected scanner finishes, ClawScan records the strongest fired
action as the top-level artifact `gate`: `block` wins over `warn`, and an
artifact with no fired rules records `"gate": "pass"`. Each fired rule is also
listed in `gateRules` with its scanner ID, rule ID, and action. Exit-code rules
include `exitCode`; JSON rules include `path` and, for `equals`, the matched
`value`. Gate actions are record-only: `block` does not stop later scanners or
the judge, and it does not change ClawScan's process exit status. For
enforcement, inspect `gate` and `gateRules` on a single run, `runs[].gate` and
`runs[].gateRules` in a batch, or `cases[].run.gate` and
`cases[].run.gateRules` in a benchmark. The human scan summary aggregates the
strongest batch action; the benchmark summary does not aggregate gate actions.

Skipped or failed scanners do not fire gate rules. A nonzero command that still
returned valid JSON has status `completed` and can fire both JSON and exit-code
rules. Valid JSON from a timeout, signal, or reserved infrastructure exit is
still preserved, but the failed scanner does not fire gate rules and its
`exitCode` is omitted.

The command must write JSON to stdout. ClawScan preserves valid stdout as the
scanner's raw evidence; empty or non-JSON stdout produces a failed scanner
result. Required environment variables are checked before any scanner starts.
Artifacts record each requirement as only `present` or `missing`.

> **Do not print secrets into evidence.** ClawScan preserves valid scanner
> stdout as raw JSON evidence, so any secret the scanner writes into that JSON
> is persisted. Values declared in `secretEnv` are redacted from scanner error
> text, but ClawScan does not rewrite raw evidence. A user-defined scanner must
> not echo its API keys, tokens, or other credentials into the JSON report it
> emits.

User-defined scanners use the same execution path as built-in command-backed
scanners. They run in the Docker sandbox by default, and declared `env` and
`secretEnv` names are added to its environment allowlist. Put every sensitive
value in `secretEnv`; values declared only in `env` are treated as non-secret
and may appear in scanner error text. ClawScan preserves valid scanner stdout
as raw JSON evidence, so scanner authors must not print secrets into that JSON.
Use `--sandbox off` only when you intentionally want the command to run on the
host. User-defined scanners are local to the resolved config and do not appear
in the built-in `clawscan scanners` catalog.

> **Trust boundary:** only load user-defined scanners from config files you
> control. A scanner entry is executable code. The default sandbox limits its
> host access, but does not make an untrusted command safe to run.

## Target kinds

Clawscan classifies each explicit target before dispatching scanners and records
the result in the artifact `target.kind` field:

| Kind | Detected when | Notes |
| --- | --- | --- |
| `skill` | default for local files and directories | Historical behavior; a directory usually holds `SKILL.md`. |
| `plugin` | directory (or manifest file) holds `openclaw.plugin.json` | OpenClaw plugin. The stable manifest `id` is recorded in `target.id`; host paths are never used as identity. |
| `url` | `http`/`https` input | API-backed and static scanners skip URLs. |

The built-in `clawhub` profile runs `skillspector` and `clawscan-static` for
`plugin` targets as it does for skills. VirusTotal and Socket also support
plugins when selected explicitly or through a custom profile. Other scanners
that assume skill layouts return an explicit `skipped` result naming the
unsupported kind, and adapters can opt in per kind as upstream tools add plugin
support. A directory carrying both `SKILL.md` and `openclaw.plugin.json` is
rejected as ambiguous rather than guessed; point Clawscan directly at the
desired manifest to disambiguate a valid dual-layout package.

Plugin targets are never auto-discovered. Zero-target discovery still scans only
child skill directories under `./skills`; pass a plugin directory explicitly to
avoid silently scanning arbitrary package directories. Pointing Clawscan at an
`openclaw.plugin.json` file scans the surrounding plugin directory.

Plugin ids follow OpenClaw's install grammar, including `@scope/name` ids.
Manifests accept the same JSON5 syntax as OpenClaw, including comments, trailing
commas, single-quoted strings, and unquoted keys.

## Available scanners

> **Want to add your scanner to the list?** Follow the guide in [docs/scanners.md](docs/scanners.md#adding-a-built-in-scanner-adapter)

| ID | Name | Repo | Description | Required env vars | Local dependency setup |
| --- | --- | --- | --- | --- | --- |
| `agentverus` | AgentVerus | [repo](https://github.com/agentverus/agentverus-scanner) | Local file or directory scanner invoked through agentverus-scanner. | none | `npm install --save-dev agentverus-scanner` |
| `aig` | Tencent AI-Infra-Guard | [repo](https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan) | Tencent Zhuque Lab's local directory scanner invoked through `aig-skill-scan`. Produces SARIF 2.1.0 with SkillTrustBench T01-T09 evidence. | `LLM_API_KEY` or `OPENAI_API_KEY`<br><details><summary>Optional config</summary><code>DEFAULT_MODEL</code>, <code>DEFAULT_BASE_URL</code>, <code>DEFAULT_MODEL_CONTEXT_WINDOW</code>, <code>LOG_LEVEL</code>.</details> | `pip install aig-skill-scan` |
| `cisco` | Cisco AI Defense skill-scanner | [repo](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory scanner invoked through `skill-scanner` with JSON report output. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers. | none<br><details><summary>Optional config</summary><code>SKILL_SCANNER_LLM_API_KEY</code>, <code>SKILL_SCANNER_LLM_PROVIDER</code>, <code>SKILL_SCANNER_LLM_MODEL</code>, <code>SKILL_SCANNER_LLM_BASE_URL</code>, <code>SKILL_SCANNER_LLM_USER</code>, <code>SKILL_SCANNER_LLM_API_VERSION</code>, <code>SKILL_SCANNER_LLM_FORCE_JSON_OBJECT</code>, <code>SKILL_SCANNER_META_LLM_API_KEY</code>, <code>SKILL_SCANNER_META_LLM_MODEL</code>, <code>SKILL_SCANNER_META_LLM_BASE_URL</code>, <code>SKILL_SCANNER_META_LLM_API_VERSION</code>, <code>AWS_PROFILE</code>, <code>AWS_REGION</code>, <code>GOOGLE_APPLICATION_CREDENTIALS</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>AI_DEFENSE_API_KEY</code>, <code>AI_DEFENSE_API_URL</code>.</details> | `uv pip install cisco-ai-skill-scanner` |
| `clawscan-static` | ClawScan Static | [repo](https://github.com/openclaw/clawscan) | Built-in deterministic text scanner for high-signal risky skill and OpenClaw plugin patterns. | none | skipped; built in |
| `relyable` | Relyable | [repo](https://github.com/veriker/relyable) | Functional re-derivation evidence: does the skill still do what its docs claim, recomputed? Emits the strongest grade that applies. `exogenous`: a declared `rederive.json` property manifest (idempotence / round-trip), with both sides of the relation computed from the skill's own code and the result mutation-tested against vacuity. `self_spec`: re-runs the author's own committed oracle (shipped tests or documented I/O examples). `cold_golden`: when an LLM key is set, a code-blind model infers goldens from SKILL.md alone and abstains unless the docs pin exact behavior; divergences are reported as unconfirmed, never as accusations. `non_rederivable`: the honest floor, never a fabricated pass. Functional axis only; complements the security scanners and does not detect malware or prompt injection. Skill code runs only inside the Docker sandbox (or with an explicit opt-in), in a scrubbed environment, and the scanner fails closed otherwise. Not preinstalled in the `clawscan-runtime` image. | none<br><details><summary>Optional config</summary><code>RELYABLE_SCAN_ALLOW_HOST_EXEC</code> — explicit ack that the host is disposable when running with <code>--sandbox off</code>.<br><br><code>RELYABLE_LLM_API_KEY</code> (+ <code>RELYABLE_LLM_PROVIDER</code> <code>anthropic|openai</code>, <code>RELYABLE_LLM_MODEL</code>, <code>RELYABLE_LLM_BASE_URL</code>) — explicit per-scanner opt-in that enables the <code>cold_golden</code> lane; key presence only is ever recorded in the payload. Generic <code>ANTHROPIC_API_KEY</code>/<code>OPENAI_API_KEY</code> are honored by standalone <code>relyable-scan</code> but are deliberately not auto-forwarded by ClawScan.</details> | `clawscan install relyable` — not preinstalled in the runtime image |
| `skillspector` | NVIDIA SkillSpector | [repo](https://github.com/NVIDIA/skillspector) | Local skill or OpenClaw plugin file/directory scanner. Uses LLM mode when provider env vars are set; otherwise runs with `--no-llm`. | none<br><details><summary>Optional config</summary><code>SKILLSPECTOR_PROVIDER</code>, <code>SKILLSPECTOR_MODEL</code>, <code>SKILLSPECTOR_MODEL_REGISTRY</code>, <code>SKILLSPECTOR_LOG_LEVEL</code>, <code>SKILLSPECTOR_SSL_VERIFY</code>, <code>NVIDIA_INFERENCE_KEY</code>, <code>OPENAI_API_KEY</code>, <code>OPENAI_BASE_URL</code>, <code>ANTHROPIC_API_KEY</code>, <code>ANTHROPIC_PROXY_ENDPOINT_URL</code>, <code>ANTHROPIC_PROXY_API_KEY</code>, <code>ANTHROPIC_PROXY_API_VERSION</code>.</details> | `uv tool install git+https://github.com/NVIDIA/skillspector.git` |
| `snyk` | Snyk Agent Scan | [repo](https://github.com/snyk/agent-scan) | Local skill scanner invoked through `uvx snyk-agent-scan`. | `SNYK_TOKEN` | verifies `uvx` launcher |
| `socket` | Socket CLI | [repo](https://github.com/SocketDev/socket-cli) | Local file or directory scanner using Socket's public CLI full-scan path. | `SOCKET_CLI_API_TOKEN` | `npm install -g socket` |
| `virustotal` | VirusTotal API | [docs](https://docs.virustotal.com/reference/file) | API-backed local file hash lookup. Skill and OpenClaw plugin directories are scanned as deterministic ZIP archives. | `VIRUSTOTAL_API_KEY` | skipped; API-backed |
