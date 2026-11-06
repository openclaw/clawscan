# Judge Harness

`--judge` hands scanner evidence to an external command so it can inspect the
skill, do its own research in the scan workspace, and write a final JSON
verdict. The judge is any tool that reads the rendered prompt and writes a JSON
object that matches the output schema:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge 'codex exec --cd {{ workspace }} --output-last-message {{ output }} - < {{ prompt:./prompt.md }}'
```

ClawScan is judge-agnostic. It renders the prompt, prepares the workspace, runs
the command, and records the command's result. It does not know which model or
harness the command uses, and the profile name never changes judge behavior.
Checks that belong to a particular judge, such as an input-size limit or proof
that the model read workspace files, belong inside that judge command. A judge
with an input limit should enforce it and fail with a clear error; ClawScan
records that error as the judge failure.

Supported `--judge` placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary directory containing the copied skill, scanner JSON, and metadata. |
| `{{ judge_sandbox }}` | `danger-full-access` inside ClawScan's Docker sandbox, otherwise `read-only`. |
| `{{ prompt }}` | Render `./prompt.md` and pass the rendered prompt file path. |
| `{{ prompt:<path> }}` | Render a specific prompt template and pass that file path. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and pass that file path. |
| `{{ output_schema:<path> }}` | Copy a specific schema file and pass that file path. |
| `{{ output }}` | File path where the judge should write its final JSON object. |

Prompt templates rendered through `{{ prompt:<path> }}` can reference
`{{ scanners.<id> }}` (raw scanner JSON), `{{ scanner_results }}` (every
scanner's `status`, `error` and unchanged raw report, keyed by scanner id),
`{{ run_context }}` (target kind and id, plus the `--context` JSON),
`{{ target.files }}` (bounded target file text), and, in an overview prompt, `{{ judge.result }}` (the completed
verdict as JSON). Referencing `{{ judge.result }}` without a completed verdict
fails the command before it starts.

## Judge workspace

Every profile gets the same workspace layout:

| Path | Contents |
| --- | --- |
| `artifact/` | The exact copied target. |
| `scanners/<scanner>.json` | Each scanner's complete raw evidence (`null` when a scanner has none). |
| `metadata.json` | ClawScan run metadata: `schemaVersion`, `target`, `scanners`, the copied-artifact manifest under `workspace.artifact`, and `context` when the run has a `--context` file. |
| `prompt.md`, `schema.json` | The rendered prompt and copied output schema, when the command references them. |
| `judge.json` | Overview step only: the completed judge result the overview explains. |

## Results, failures, and retries

A judge command that fails keeps its own error. Partial stdout, such as a JSON
progress line printed before the command exits non-zero, never replaces that
error, and a failed command is not retried.

A judge command that exits successfully but writes no JSON (including never
writing `{{ output }}`), invalid JSON, or a JSON value that is not an object is
run once more in a fresh workspace with the
same artifact files, scanner evidence, prompt, and output schema. A second
unusable result still fails closed. A JSON object is the judge result; ClawScan
never retries a verdict for being suspicious or malicious and does not validate
judge-specific fields.

Both attempts share the existing judge timeout budget, including workspace
preparation; retrying does not restart the timeout. A caller's shorter
whole-process deadline still takes precedence, and no retry starts after
cancellation. The artifact's `judge.attempts` records every attempt
that reached its command (`commandStarted`, status, redacted result, error, and
duration); a judge that fails during workspace preparation has no attempts. The top-level
`judge.result` is the last attempt, and consumers must still validate its output
schema and security evidence.

`judge.commandStarted` and each attempt's `commandStarted` describe the local
harness **shell**: `false` proves it was not started, `true` proves the shell
started, and omission means unknown. With the Docker sandbox, starting the host
Docker client does not prove that the container shell started, so
`commandStarted` remains unknown unless non-start is proven. A `running`
checkpoint or entry into the judge phase does not prove invocation. Shell start
does not independently prove a native/model invocation or its count; arbitrary
harnesses may fail before that point or invoke more than once. Keep provider
exposure unknown unless independently evidenced. Pre-command workspace failures
retain a failed judge with `commandStarted: false`; canceled started commands
retain failed results and attempt history. A canceled run is never complete;
consumers must reject incomplete top-level artifacts before considering scanner
or judge verdicts.

## Overview step

A profile can configure an optional `overview.command` next to `judge.command`.
`--overview <cmd>` overrides it for one run and `--no-overview` skips it.
Benchmark runs skip the profile overview unless `--overview` is passed. The
overview runs once, after the judge completes, in a fresh workspace with the
same layout and placeholders plus `judge.json`. It writes a JSON object, the
same way a judge does, and ClawScan records it under the artifact's `overview`:

```json
"overview": {
  "status": "completed",
  "commandStarted": true,
  "configuredModel": "",
  "promptSha256": "...",
  "outputSchemaSha256": "...",
  "error": "",
  "durationMs": 8123,
  "result": { "summary": "...", "user_guidance": "..." }
}
```

The overview is advisory prose. It never changes the verdict, the gate, the
run's `status` or `complete`, or the CLI exit status. A failed command, invalid
output, or timeout (five minutes, separate from the judge budget) is recorded as
`status: "failed"` with the command's error; the overview is not retried. When
the judge did not complete, the overview is recorded as `status: "skipped"` and
its command never runs. Caller cancellation still cancels the whole run.

## Evidence-only judges

A profile can set `evidenceOnly: true` on its `judge` or `overview`. That
command then gets scanner evidence only:

- its workspace has no `artifact/` copy, and `metadata.json` omits the copied
  file manifest, the target input and its resolved host path, keeping only the
  target `kind` and `id`;
- `{{ target.files }}` and the ClawHub parity prompt (`clawhub/prompt.md`) fail
  before the command starts;
- scanner reports stay unchanged under `scanners/` and in `{{ scanner_results }}`,
  including any paths the scanners recorded.

The ClawHub evidence judge treats publisher trust as provenance: only a
publisher verified by ClawHub in the job `context` can make an @openclaw
package trusted by default. A name, README, manifest or publisher claim quoted
in scanner results never does.

The setting applies only while the profile's own command runs. A `--judge` or
`--overview` override is the general interface and keeps the full workspace.

## ClawHub judge

The `clawhub` and `clawhub-aig` profiles judge skills and plugins with an
evidence-only Codex run (`gpt-6.1-sol`, high reasoning, Standard service). The
bundled `clawhub/evidence-judge.md` prompt carries `{{ run_context }}` and
`{{ scanner_results }}`, frames every scanner report (including artifact text a
scanner quoted) as untrusted data, and treats missing, failed or partial
coverage as uncertainty rather than evidence of safety. The verdict matches
`clawhub/evidence-judge.schema.json`: the typed `verdict`, `confidence`,
`dimensions` and `scan_findings_in_context`. The overview uses
`clawhub/evidence-overview.md` the same way, adding `{{ judge.result }}`.

Codex cannot read the artifact, run commands, write files or search the web.
The profile passes `--sandbox read-only`, `-c web_search=disabled`,
`-c skills.include_instructions=false`, and `--disable` for `shell_tool`,
`unified_exec`, `view_image`, `multi_agent`, `goals`, `apps`, `plugins`,
`browser_use`, `computer_use`, `image_generation`, `hooks`, `code_mode_host`,
`multi_agent_v2` and `sleep_tool`. Checked against codex-cli 0.164.0 by
capturing its actual Responses requests on a loopback stub:

- The shell, exec, image, web-search and goal tools are no longer offered. A
  forced `exec_command`, `shell` or `local_shell` call is rejected as
  `unsupported call` and does not run.
- GPT-6 models are still offered `functions.exec` (code mode, which nests
  `apply_patch` and the MCP resource tools). With `code_mode_host` disabled a
  call returns `code-mode host is disabled` and runs nothing; even with it
  enabled, `apply_patch` is rejected by the read-only sandbox, no MCP server is
  configured, and the JavaScript isolate has no file or process access.
- `request_user_input`, `wait` and the `collaboration` agent tools remain
  offered; no supported 0.164 setting removes them for GPT-6 models. A spawned
  agent inherits the same disabled tools and the same evidence-only workspace,
  so it reaches nothing the judge cannot; it can only add model calls inside the
  judge's time budget.

Recheck the offered tools whenever the pinned Codex CLI changes.

## ClawHub Decisions judge

The Decisions API harness stays supported through `--judge`:

```bash
clawscan ./my-skill --profile clawhub --judge \
  'clawscan-decisions-judge --workspace {{ workspace }} --instructions {{ prompt:clawhub/decisions.md }} --output-schema {{ output_schema:clawhub/output.schema.json }} --output {{ output }}'
```

`clawscan-decisions-judge` is a
standard-library Python command shipped in the runtime image
(`docker/clawscan-runtime/judges/clawscan_decisions_judge.py`). It reads the
judge workspace and sends one `POST /v1/decisions` request:

- `input`: a developer message with the bundled `clawhub/decisions.md` policy,
  then a user message with an `input_text` part holding the exact artifact text
  files between random per-run boundary markers, and an `input_json` part with
  run metadata (target kind/id, scanner statuses, run context), per-scanner
  summaries, normalized scanner findings (SARIF results and common
  `findings`/`issues`/`vulnerabilities` arrays, highest severity first), and the
  artifact manifest with sizes and SHA-256 digests. Scanner statuses and errors
  from `metadata.json` and SARIF `invocations` (failed executions and tool
  notifications) are kept as coverage gaps. Any scanner's SARIF or JSON report
  under `scanners/` is ingested the same way, including a single plugin-wide
  A.I.G SARIF report. The policy treats severity as a hypothesis, never as
  evidence of malice.
- Gap and provenance evidence: the remote model cannot open
  `scanners/<id>.json`, so the judge projects it into the request. Every list
  under `analysis_completeness` (`ledger_exceptions`, `scope_exclusions`,
  `references`, `limitations`, incomplete `analyzer_statuses`, and so on),
  top-level limitation/gap lists, components with limitations, incomplete
  inspection, or executable code (`componentGaps`), and bounded `metadata`
  provenance become `{total, countsBy, counts, records, omitted}` objects.
  Records are a group-balanced sample of up to 24 path-aware entries (reason,
  phase, message, lines); counts cover up to 32 groups plus
  `otherGroups`/`otherEntries`. `bundled_reports` children keep their `rootPath`,
  their own completeness gaps, component gaps, provenance, and findings, with
  child paths prefixed by `rootPath`.
- Plugin dependencies: for plugin targets, files under `node_modules` at any
  depth are deliberately excluded from the artifact text, manifest, and budget,
  matching the plugin scanner, and reported only as
  `artifactCounts.excludedDependencies` (`files`, `bytes`, `reason`). That is
  a scope decision, not missing coverage. The copied artifact is not modified,
  and skill targets keep `node_modules` in scope.
- `questions`: a `verdict` choice (`benign`, `suspicious`, `malicious`, each
  with a precise description), five `dimension.<name>` choices (`ok`, `note`,
  `concern`), eight `signal.<name>` predicates (exfiltration, tool poisoning,
  backdoor, remote code execution, persistence, credential access, obfuscation,
  destructive actions), and a `finding.<n>` predicate ("expected for the stated
  purpose?") for up to 25 of the highest-severity findings. Question
  instructions are static: a finding question names only the finding's stable
  `index` in the evidence JSON, and no scanner or artifact text is ever
  interpolated into `questions[].instructions`.

The judge maps the answers onto `clawhub/output.schema.json` and validates its
own output against that schema before writing it:

| Output field | Source |
| --- | --- |
| `verdict` | `verdict` choice |
| `confidence` | verdict choice confidence: `high` at 0.8 or more, `medium` at 0.5 or more, otherwise `low` |
| `dimensions.<name>.status`, `.confidence` | `dimension.<name>` choice and its confidence |
| `scan_findings_in_context[]` | `finding.<n>` predicates: `ruleId` (rule plus location), `scanner`, `expected_for_purpose` (probability of 0.5 or more), `probability` |
| `decision` | `api`, `endpointHost`, `requestedModel`, API-reported `model`, `latencyMs`, `httpAttempts`, `usage`, input accounting, verdict probabilities, and `signals` |

Prose (`summary`, dimension details, finding notes, `user_guidance`) comes from
the overview step, not the judge.

The judge owns its checks. Binary and non-UTF-8 files are listed in the manifest
but not sent; text files are sent whole up to 120,000 characters each and
600,000 in total, with larger files excerpted (head and tail) and the remainder
listed as omitted. Findings are capped at 200 (`--max-findings`). The fully
assembled evidence object, including the manifest and every count, must fit
200 KiB, 10,000 JSON values, and depth 32 (the API allows 256 KiB). If it does
not, the judge trims findings, then the manifest, then gap samples and bundled
children, recording `findingCounts.omitted`, `artifactCounts.manifestOmitted`,
and per-list `omitted`. All accounting fields exist before the first measurement, and the exact object is re-checked after every mutation. The judge fails before sending if nothing is left to trim or the final check fails. The
final size, value count, and depth are recorded in
`decision.input.evidenceJson`. The assembled input must fit `--max-input-chars`
(default 1,000,000, overridable with `DECISIONS_MAX_INPUT_CHARS`); otherwise the
judge exits 2 with `decisions judge input too large: ...` before sending any
request. This is a character budget, not a token guarantee; a model context
rejection still surfaces as a Decisions API error. Answers are validated
strictly, independent of the output schema. There must be exactly one answer
per question, with known names, no duplicates, and the asked type. Choices
must be allowed values. Every probability and confidence must be a finite
number in [0, 1]. Any refusal anywhere in the response is terminal. Any refused question, HTTP error (with the API's message, type, and
code), network failure, or malformed answer exits 1 with the real error on
stderr, so ClawScan records a failed judge and never retries it. HTTP 429 and 5xx
responses are retried up to twice within the judge's timeout, honoring
`Retry-After`.

Configuration is environment-only:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DECISIONS_API_KEY` | `OPENAI_API_KEY` | Bearer key for the Decisions endpoint. |
| `DECISIONS_BASE_URL` | `OPENAI_BASE_URL`, then `https://api.openai.com/v1` | Endpoint base; `/v1` is appended when missing. |
| `DECISIONS_MODEL` | `gpt-6-luna` | Decisions model. ClawRouter uses `openai/gpt-6-luna`. |
| `DECISIONS_MAX_INPUT_CHARS` | `1000000` | Default input limit. |

The ClawHub judge and overview run Codex with `CODEX_API_KEY` or
`OPENAI_API_KEY`; the overview uses `gpt-6-luna` (override with
`OVERVIEW_MODEL`) and low reasoning effort. When `OPENAI_BASE_URL` is set, both
route Codex through that
OpenAI-compatible Responses endpoint, such as ClawRouter
(`OPENAI_BASE_URL=https://clawrouter.openclaw.ai/v1`,
`OVERVIEW_MODEL=openai/gpt-6-luna`).

The ClawHub parity prompt, `clawhub/prompt.md`, asks the judge to inspect the
artifact. It stays embedded for `cmd/verify-clawhub-prompt` parity tooling and
`--judge` comparisons, but the bundled profiles do not use it.

## Partial SkillSpector evidence

When a judge is configured, a usable partial SkillSpector report reaches the
judge instead of failing the scan. These scanner results retain
`status: "partial"` and add `reportPolicy: "judge-gaps"`. Their `raw` report and
saved scanner output retain the original findings, completeness accounting,
limitations, and provenance. The judge workspace contains the complete raw
report at `scanners/skillspector.json` and the exact copied artifact in
`artifact/`. Without a judge, partial coverage fails the scanner as before. The
profile name does not change this classification. When a judge is configured,
SkillSpector reports must also be nonempty JSON objects, and bundled reports
qualify only through the bundled-partial checks below.

Eligibility requires an unambiguous structured report with explicitly successful
execution at both report and completeness levels, partial accounting, component
and issue arrays, and usable gap records. Native commands must finish with exit
0 or 1; missing, malformed, crashed, or unsuccessful output remains failed.
There is no minimum coverage percentage, and configured security gate rules
still apply to usable partial evidence.

Bundled plugin evidence may retain original child reports in
`bundled_reports: [{"rootPath": "skills/example", "report": {...}}, ...]`.
This one-level wrapper qualifies only when every unique canonical relative root
has usable original evidence and at least one child is partial. Partial children
use the same report checks; complete children retain strict completion checks
and typed evidence/error/fatal guards, and require `execution_successful: true`
at both report and `analysis_completeness` levels with `is_complete: true` in
that accounting. Legacy complete reports outside this wrapper are unchanged.
Nested aggregates, duplicate keys or roots,
conflicting control aliases, invalid paths, and failed children reject the wrapper.
Aggregate risk status and findings stay unchanged; the wrapper's execution flags
and partial accounting do not synthesize completed coverage. The judge resolves
original child component paths beneath each `artifact/<rootPath>/`.

The judge weighs material gaps against the exact artifact. A prose-writing judge
explains investigation and residual uncertainty in its own output; with the
bundled ClawHub profiles the overview step writes that explanation. The judge
may return benign, suspicious, or malicious; partial evidence alone
determines none of these. Neither complete scanner coverage nor inspecting every
gap is required.

Consumers must explicitly support the partial status and policy pair. A run with
this evidence can have top-level `status: "completed"` and `complete: true` only
after its judge completes. Reject incomplete runs, failed judges, and
unrecognized partial results. Continue enforcing artifact identity, sandbox
requirements, and genuine secret, malicious, and unsafe-bytecode checks.

## ClawHub prompt rendering

The bundled `clawhub/prompt.md` is rendered into the ClawHub prompt layout,
selected by that prompt file rather than by profile name. The pre-scan malicious
signal comes from the run context when present, otherwise from A.I.G SARIF
evidence; injection signals come only from the run context.

Partial reports can carry one accounting row per excluded or partially inspected
file. In the ClawHub prompt, `analysis_completeness.ledger_exceptions` and
`scope_exclusions` (grouped by `reason_code`) and `references` (grouped by
`status`) are summarized as `{summarized, total, counts_by_<key>, sample,
sample_omitted, note}`. Counts cover up to 32 groups, with any remainder in
`other_<key>_groups` and `other_<key>_entries`. The sample takes the first three
rows of each group in count order, up to 24 bounded rows and 12,000 characters.
The full lists stay in `scanners/skillspector.json` in the judge workspace and
in the scanner's `raw` evidence; summarization never changes scanner status,
findings, or gates. ClawScan applies no prompt-size budget; the judge command
owns any input limit.

## Live judge check

Maintainers can manually run the **CI** workflow with **judge-inspection** enabled,
or dispatch **Live Judge Smoke** directly. The check uses the repository's
`OPENAI_API_KEY`, the Decisions judge, and a pinned Codex CLI for the overview
to judge a harmless local package through the `clawhub` profile, verifies that
the judge completed with a verdict and the overview with a summary, and retains
the redacted report for seven days.

This check uses GitHub-hosted Ubuntu 22.04 after a paired GitHub-hosted test found
a nested bubblewrap setup failure on Ubuntu 24.04. That result does not establish
that other Ubuntu 24.04 hosts, including Blacksmith, fail or that Ubuntu 22.04
cannot time out. It preserves the judge's read-only sandbox and uses scanner
fixtures to isolate the judge. It does not perform a full security scan or
approve or publish a package. Normal push and pull-request CI do not run this
paid, live check.
