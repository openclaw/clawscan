# Judge Harness

The judge is optional.

Without `--judge`, ClawScan runs scanners and writes raw evidence. With
`--judge`, ClawScan prepares a temporary workspace, interpolates placeholders,
runs the command through the platform shell, and records the resulting JSON
object.

## Command Shape

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner virustotal \
  --judge 'codex exec --cd {{ workspace }} \
    --model gpt-5.5 \
    --sandbox read-only \
    --skip-git-repo-check \
    --ignore-user-config \
    -c approval_policy=never \
    -c model_reasoning_effort=high \
    --output-schema {{ output_schema:./schemas/security-verdict.schema.json }} \
    --output-last-message {{ output }} \
    --ephemeral \
    --json \
    - < {{ prompt:./prompts/security-review.md }}' \
  --output ./clawscan-judged.json
```

The command must produce a JSON object on stdout or write one to `{{ output }}`.
If it produces invalid JSON, a JSON array, or no JSON, ClawScan records a failed
judge result.

## Placeholders

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary judge workspace. |
| `{{ prompt }}` | Render `./prompt.md`, write it to the workspace, and interpolate that path. |
| `{{ prompt:<path> }}` | Render a specific prompt template path. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and interpolate that path. |
| `{{ output_schema:<path> }}` | Copy a specific schema path. |
| `{{ output }}` | Path where the judge should write final JSON. |

The workspace contains:

- `artifact/` with copied target files.
- `scanners/<id>.json` for each scanner result.
- `metadata.json` with target metadata, scanner metadata, and copied/omitted
  target-file records.

## Prompt Templates

Prompt authors decide where scanner evidence goes:

```md
SkillSpector evidence:

{{ scanners.skillspector }}

VirusTotal evidence:

{{ scanners.virustotal }}
```

Target files can also be included:

```md
{{ target.files }}
```

If a prompt references a scanner that was not requested, ClawScan fails clearly
instead of inserting an empty block.

## Why This Is External

ClawScan does not own the model-provider abstraction. Codex, another agent
harness, the OpenAI Responses API, a local script, or a future evaluator can all
sit behind `--judge`. That keeps scanner orchestration separate from judgment.
