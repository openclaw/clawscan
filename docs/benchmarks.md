# Benchmarks

ClawScan can run the same scanner and judge setup over a supported benchmark.

Supported benchmarks:

```text
cuhk-zhuque/SkillTrustBench
OpenClaw/clawhub-security-signals
```

SkillTrustBench is the default benchmark. Use the canonical Hugging Face ID or
the short alias `SkillTrustBench`, or omit the value after `--benchmark`.

```bash
clawscan \
  --benchmark \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

The first SkillTrustBench run downloads the versioned
`benchmark_full_v1.0.zip` archive into the user cache. ClawScan then extracts
only the requested case directory into a temporary skill target for scanning.

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
| `--split <name>` | `benchmark` for SkillTrustBench, `eval_holdout` for OpenClaw | Hugging Face split to run. SkillTrustBench accepts `benchmark`; OpenClaw accepts `train`, `validation`, `test`, and `eval_holdout`. |
| `--limit <n>` | `0` | Maximum rows to run. `0` means all rows in the selected split. |
| `--offset <n>` | `0` | Row offset for reproducible chunks. |

Use `--limit` and `--offset` while iterating locally. Use `--limit 0` only when
you intend to run the whole split.

## Row Mapping

The benchmark loader fetches rows from Hugging Face and maps each row into a
temporary skill directory.

For SkillTrustBench:

- `judgment` becomes the expected verdict.
- `id` becomes the benchmark case ID and `skillSlug`.
- `risk_labels`, `source`, `base_category`, `primary_pattern`,
  `attack_pattern`, and `skill_path` are copied into expected context.
- `skill_path` identifies the case directory inside `benchmark_full_v1.0.zip`.
  ClawScan safely extracts that one directory and requires it to contain
  `SKILL.md`.

For `OpenClaw/clawhub-security-signals`:

- `skill_md_content` becomes `SKILL.md`.
- `skill_bundle_content` restores any additional files.
- `clawscan_verdict`, `clawscan_confidence`, `clawscan_model`,
  `clawscan_summary`, and `clawscan_context` are copied into the case's expected
  metadata.

Each benchmark case then runs the normal one-off ClawScan path. That keeps
scanner output, prompt rendering, judge execution, env validation, and secret
redaction consistent between one-off scans and benchmark runs.
