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

For the OpenClaw benchmark, `--output ./clawscan-benchmark.json` also writes a
submission-friendly `./predictions.jsonl` file. Use `--predictions-output` to
choose a different path:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json \
  --predictions-output ./submission/predictions.jsonl
```

## Splits and Bounds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--split <name>` | `benchmark` for SkillTrustBench, `eval_holdout` for OpenClaw | Hugging Face split to run. SkillTrustBench accepts `benchmark`; OpenClaw accepts `train`, `validation`, `test`, and `eval_holdout`. |
| `--limit <n>` | `0` | Maximum rows to run. `0` means all rows in the selected split. |
| `--offset <n>` | `0` | Row offset for reproducible chunks. |
| `--predictions-output <path>` | Next to `--output` for OpenClaw only | Write the lightweight leaderboard submission JSONL file. |

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

## Predictions JSONL

`predictions.jsonl` is the canonical lightweight submission file for the
OpenClaw security-signals leaderboard workflow. Each line is one JSON object:

```json
{"id":"case-1","prediction":"clean"}
{"id":"case-2","prediction":"suspicious"}
{"id":"case-3","prediction":"malicious"}
```

`id` is the benchmark row ID. `prediction` must be one of `clean`,
`suspicious`, or `malicious`.

Prediction extraction prefers a completed judge result with a `prediction`,
`verdict`, or `status` field. If no judge verdict is present, ClawScan can use a
single scanner raw `prediction`, `verdict`, or `status` field. For the built-in
`clawscan-static` baseline, ClawScan derives the prediction from static finding
severity: no findings is `clean`, medium findings are `suspicious`, and high
findings are `malicious`.

Benchmark artifacts keep the canonical prediction next to the expected verdict
and record whether the case was `correct`, `incorrect`, `abstained`,
`unscorable`, or `error`.

## Security Signals Leaderboard Submissions

The v1 Security Signals leaderboard submission path is GitHub PRs to this repo.
The Hugging Face Space is a display and convenience preview surface only; it
does not publish official rows.

1. Run ClawScan locally against the full OpenClaw benchmark split.
2. Put `metadata.json` and `predictions.jsonl` in a new
   `leaderboard/submissions/<run-id>/` directory.
3. Optionally include a full `artifact.json` from the benchmark run.
4. Validate locally with `clawscan validate-submission`.
5. Open a PR. CI recomputes metrics and uploads a score preview artifact.
6. After review and merge, the post-merge publish workflow updates the private
   results dataset when Hugging Face credentials are configured.

Full benchmark run:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

Submission directory:

```text
leaderboard/submissions/<run-id>/
  metadata.json
  predictions.jsonl
  artifact.json        # optional full ClawScan benchmark artifact
```

Minimal `metadata.json`:

```json
{
  "schemaVersion": "clawscan-security-signals-submission-v1",
  "benchmark": {
    "dataset": "OpenClaw/clawhub-security-signals",
    "split": "eval_holdout",
    "revision": "<hugging-face-dataset-sha>"
  },
  "system": {
    "name": "example-system",
    "role": "community"
  },
  "verificationStatus": "artifact-validated"
}
```

Provenance-rich metadata can use the same required fields and make the system
name/role more specific, such as `clawhub-production`, `community-example`, or
a scanner/profile/judge name. Keep secrets out of metadata and artifacts.

Validate before opening a PR:

```bash
clawscan validate-submission leaderboard/submissions/<run-id>
```

The validator rejects duplicate case IDs, missing case IDs, unknown case IDs,
invalid prediction labels, mismatched dataset IDs, unsupported splits, and
missing dataset revision metadata. It recomputes loose non-clean metrics:
`suspicious` and `malicious` count as positive, and `clean` counts as negative.

Verification statuses:

| Status | Meaning |
| --- | --- |
| `artifact-validated` | CI validated submitted artifacts and recomputed score math. Scanner or judge execution was not rerun by OpenClaw. |
| `clawhub-production` | Row represents a ClawHub/OpenClaw-maintained production-style reference or baseline. |
| `openclaw-rerun` | Reserved for future rows rerun by OpenClaw-controlled infrastructure. |

The Gradio Space upload flow can validate and preview a `predictions.jsonl`
file before you open a PR. That upload does not publish results. Official
leaderboard rows come from reviewed and merged PR submissions.

Operational source files:

- `leaderboard/submissions/README.md` documents the repo submission shape and
  seed rows.
- `leaderboard/results/README.md` documents the private results dataset and
  publish path.
- `leaderboard/space/README.md` documents the private Gradio Space scaffold and
  local smoke flow.
