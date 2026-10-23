# Judge Harness

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

## Live inspection check

Maintainers can manually run the **CI** workflow with **judge-inspection** enabled,
or dispatch **Judge Artifact Inspection Smoke** directly. The check uses the
repository's `OPENAI_API_KEY` and a pinned Codex CLI to inspect a harmless local
package through the `clawhub` profile. It verifies the completed receipt, the
package manifest's SHA-256, and the inspected path, then retains the redacted
report for seven days.

This check runs on Ubuntu 22.04 because Ubuntu 24.04 rejects the judge's nested
bubblewrap setup. It preserves the judge's read-only sandbox and uses scanner
fixtures to isolate artifact inspection. It does not perform a full security
scan or approve or publish a package. Normal push and pull-request CI do not run
this paid, live check.
