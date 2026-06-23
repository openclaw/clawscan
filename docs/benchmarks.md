# Benchmarks

ClawScan can run the same scanner and judge setup over a supported benchmark.

V1 intentionally supports one benchmark:

```text
OpenClaw/clawhub-security-signals
```

## Run the OpenClaw Benchmark

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

## Splits and Bounds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--split <name>` | `eval_holdout` | Hugging Face split to run. Accepted splits are `train`, `validation`, `test`, and `eval_holdout`. |
| `--limit <n>` | `0` | Maximum rows to run. `0` means all rows in the selected split. |
| `--offset <n>` | `0` | Row offset for reproducible chunks. |

Use `--limit` and `--offset` while iterating locally. Use `--limit 0` only when
you intend to run the whole split.

## Row Mapping

The benchmark loader fetches rows from Hugging Face and maps each row into a
temporary skill directory:

- `skill_md_content` becomes `SKILL.md`.
- `skill_bundle_content` restores any additional files.
- `clawscan_verdict`, `clawscan_confidence`, `clawscan_model`,
  `clawscan_summary`, and `clawscan_context` are copied into the case's expected
  metadata.

Each benchmark case then runs the normal one-off ClawScan path. That keeps
scanner output, prompt rendering, judge execution, env validation, and secret
redaction consistent between one-off scans and benchmark runs.
