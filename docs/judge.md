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

## Judge workspace

Every profile gets the same workspace layout:

| Path | Contents |
| --- | --- |
| `artifact/` | The exact copied target. |
| `scanners/<scanner>.json` | Each scanner's complete raw evidence (`null` when a scanner has none). |
| `metadata.json` | ClawScan run metadata: `schemaVersion`, `target`, `scanners`, the copied-artifact manifest under `workspace.artifact`, and `context` when the run has a `--context` file. |
| `prompt.md`, `schema.json` | The rendered prompt and copied output schema, when the command references them. |

## Results, failures, and retries

A judge command that fails keeps its own error. Partial stdout, such as a JSON
progress line printed before the command exits non-zero, never replaces that
error, and a failed command is not retried.

A judge command that exits successfully but writes no JSON, invalid JSON, or a
JSON value that is not an object is run once more in a fresh workspace with the
same artifact files, scanner evidence, prompt, and output schema. A second
unusable result still fails closed. A JSON object is the judge result; ClawScan
never retries a verdict for being suspicious or malicious and does not validate
judge-specific fields.

Both attempts share the existing judge timeout budget, including workspace
preparation; retrying does not restart the timeout. A caller's shorter
whole-process deadline still takes precedence, and no retry starts after
cancellation. The artifact's `judge.attempts` records every attempt's
`commandStarted`, status, redacted result, error, and duration. The top-level
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

## Partial SkillSpector evidence

When a judge is configured, a usable partial SkillSpector report reaches the
judge instead of failing the scan. These scanner results retain
`status: "partial"` and add `reportPolicy: "judge-gaps"`. Their `raw` report and
saved scanner output retain the original findings, completeness accounting,
limitations, and provenance. The judge workspace contains the complete raw
report at `scanners/skillspector.json` and the exact copied artifact in
`artifact/`. Without a judge, partial coverage fails the scanner as before. The
profile name does not change this classification.

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

The judge independently investigates material gaps in the exact artifact and
explains investigation and residual uncertainty in dimension details and user
guidance. It may return benign, suspicious, or malicious; partial evidence alone
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
`OPENAI_API_KEY` and a pinned Codex CLI to judge a harmless local package through
the `clawhub` profile, verifies that the judge completed with a verdict, and
retains the redacted report for seven days.

This check uses GitHub-hosted Ubuntu 22.04 after a paired GitHub-hosted test found
a nested bubblewrap setup failure on Ubuntu 24.04. That result does not establish
that other Ubuntu 24.04 hosts, including Blacksmith, fail or that Ubuntu 22.04
cannot time out. It preserves the judge's read-only sandbox and uses scanner
fixtures to isolate the judge. It does not perform a full security scan or
approve or publish a package. Normal push and pull-request CI do not run this
paid, live check.
