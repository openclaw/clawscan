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
