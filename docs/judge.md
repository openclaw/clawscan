# Judge Harness

`judge.commandStarted` and each parity attempt's `commandStarted` describe the
local harness **shell**: `false` proves it was not started, `true` proves the
shell started, and omission means unknown. With the Docker sandbox, starting
the host Docker client does not prove that the container shell started, so
`commandStarted` remains unknown unless non-start is proven. An independently
validated inspection receipt still retains its own evidence; it is not a
Docker/container cleanup receipt. A prepared challenge, a `running`
checkpoint, or entry into the judge phase does not prove invocation. Shell start
does not independently prove a native/model invocation or its count; arbitrary
harnesses may fail before that point or invoke more than once. Keep provider
exposure unknown unless independently evidenced. Pre-command workspace failures
retain a failed judge with `commandStarted: false`; canceled started commands
retain failed results and receipt-attempt history, never a manufactured receipt.

Receipt retries share `RunContext.Context` as well as the judge's existing
timeout. No retry starts after cancellation. Even a readable valid receipt
cannot complete a canceled run; consumers must reject incomplete top-level
artifacts before considering scanner or judge verdicts.

`--judge` hands scanner evidence to an external agent command so it can inspect
the skill, do its own research in the scan workspace, and write a final JSON
verdict:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge 'codex exec --cd {{ workspace }} --output-last-message {{ output }} - < {{ prompt:./prompt.md }}'
```

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

For the `clawhub` and `clawhub-aig` profiles, a successful judge command whose
artifact-inspection receipt fails validation is evaluated once more, in a fresh
workspace with a fresh challenge. The retry receives the same artifact files,
scanner evidence, prompt, and output schema. It must independently satisfy the
challenge, required-file hash, and inspected-path checks. A second invalid receipt
still fails closed; a valid security verdict is never retried merely for being
suspicious or malicious. Command failures, timeouts, and malformed JSON are not
retried by this policy.

Both attempts share the existing judge timeout budget, including workspace
preparation; retrying does not restart the timeout. A caller's shorter whole-process
deadline still takes precedence. The artifact's `judge.attempts` records each
attempt's status, redacted result, validation error, duration, and expected
inspection challenge/path/hash. The top-level `judge.result` is only the last
attempt, and consumers must still validate its output schema and security evidence.

## Versioned inspection receipts

The built-in `clawhub` and `clawhub-aig` judges emit version 2 receipts. The
required file has its own mandatory `required_file` string, constrained by a
single-value enum in the rendered output schema. `additional_files_inspected`
records every other inspected artifact file and may be empty. The two fields
together retain the complete inspected-file record, without requiring the model
to repeat the selected path inside an unconstrained array.

Additional paths use canonical workspace-relative `artifact/` file paths: no
empty, `.` or `..` components, artifact root, or trailing slash. The generation
schema expresses the same lexical rule as the independent Go receipt guard;
neither infers file existence or file type from a path string. The prompt requires
files, not directories, and preserves literal spaces, Unicode, and hidden names.
Workspace challenge, metadata, and scanner-report files outside `artifact/` remain
judge evidence, not artifact input paths to list in the receipt. Every inspected
additional artifact file must still be reported; no per-file enum or array cap
truncates that record. Malformed returned paths still fail and may trigger the
existing bounded retry; they are never cleaned, removed, or rewritten.

The workspace challenge and independently computed required-file hash are still
validated exactly. Neither expected value is included in the prompt or schema.
No receipt is filled in, converted, or repaired after the judge returns it. A
wrong or missing `required_file`, incorrect hash/challenge, unknown version, or
hybrid v1/v2 receipt fails closed. The runner continues to validate unversioned
v1 receipts using their original `files_inspected` membership check.

Schema templates may use `"{{ artifact_inspection.required_file }}"` as a complete
JSON string value. The runner replaces that string with the JSON-escaped selected
workspace path before execution and records the rendered schema's SHA-256.
Templates without this placeholder are unchanged.

**Consumer upgrade required:** consumers enforcing the previous receipt-key
allowlist must explicitly support v2 before a new built-in profile is deployed.
Preserve both returned fields as evidence; do not manufacture a v1 receipt or
normalize a wrong path. Schema/consumer tests are not proof of live provider
behavior, latency improvement, or production recovery.

## Live inspection check

Maintainers can manually run the **CI** workflow with **judge-inspection** enabled,
or dispatch **Judge Artifact Inspection Smoke** directly. The check uses the
repository's `OPENAI_API_KEY` and a pinned Codex CLI to inspect a harmless local
package through the `clawhub` profile. It verifies the completed receipt, the
package manifest's SHA-256, and the inspected path, then retains the redacted
report for seven days.

This check uses GitHub-hosted Ubuntu 22.04 after a paired GitHub-hosted test found
a nested bubblewrap setup failure on Ubuntu 24.04. That result does not establish
that other Ubuntu 24.04 hosts, including Blacksmith, fail or that Ubuntu 22.04
cannot time out. It preserves the judge's read-only sandbox and uses scanner
fixtures to isolate artifact inspection. It does not perform a full security
scan or approve or publish a package. Normal push and pull-request CI do not run
this paid, live check.
