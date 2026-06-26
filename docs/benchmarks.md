# Benchmarks

ClawScan can run the same scanner and judge setup over a supported benchmark.
The primary local result is the `clawscan-benchmark.json` artifact. It embeds
the normal per-case `clawscan-run-v1` artifacts, expected labels, scanner
statuses, and score metadata when the benchmark can be scored.

Supported benchmarks:

```text
cuhk-zhuque/SkillTrustBench
clawhub-security-signals
```

Use the benchmark catalog command to inspect supported benchmarks, source
links, split names, defaults, and env requirements:

```bash
clawscan benchmark list
```

Run SkillTrustBench with the canonical Hugging Face ID or the short alias
`SkillTrustBench`.

```bash
clawscan benchmark SkillTrustBench \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

The first SkillTrustBench run downloads the versioned
`benchmark_full_v1.0.zip` archive into the user cache. ClawScan then extracts
only the requested case directory into a temporary skill target for scanning.

## Run the ClawHub Security Signals Benchmark

```bash
clawscan benchmark clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json
```

`clawhub-security-signals` records current ClawHub production signals for
reproduction and regression checks. It is not a human-validated ground-truth
benchmark. For this benchmark, `--output ./clawscan-benchmark.json` also writes
a submission-friendly `./predictions.jsonl` file. Treat this JSONL as a derived
leaderboard/CI input; use the benchmark artifact when you need to understand why
a scanner or judge behaved a certain way. Use `--predictions-output` to choose a
different path:

```bash
clawscan benchmark clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --scanner clawscan-static \
  --output ./clawscan-benchmark.json \
  --predictions-output ./submission/predictions.jsonl
```

## Splits and Bounds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--split <name>` | `benchmark` for SkillTrustBench, `eval_holdout` for ClawHub Security Signals | Hugging Face split to run. SkillTrustBench accepts `benchmark`; ClawHub Security Signals accepts `train`, `validation`, `test`, and `eval_holdout`. |
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

For `clawhub-security-signals`:

- `skill_md_content` becomes `SKILL.md`.
- `skill_bundle_content` restores any additional files.
- `clawscan_verdict`, `clawscan_confidence`, `clawscan_model`,
  `clawscan_summary`, and `clawscan_context` are copied into the case's expected
  metadata.

Each benchmark case then runs the normal one-off ClawScan path. That keeps
scanner output, prompt rendering, judge execution, env validation, and secret
redaction consistent between one-off scans and benchmark runs.

## Derived Predictions JSONL

`predictions.jsonl` is the derived lightweight submission file for the OpenClaw
security-signals leaderboard workflow. Each line is one JSON object:

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

## Reading Local Results

Start with the benchmark artifact summary:

- `summary.caseCount` is the number of cases attempted.
- `summary.expectedVerdicts` shows the label distribution.
- `summary.scannerStatuses` counts completed, skipped, and errored scanner runs
  by scanner ID.
- case-level evaluation records whether ClawScan could score the prediction and
  whether it matched the expected verdict.

Then inspect individual cases:

- `cases[].expected` explains the expected verdict and benchmark context.
- `cases[].run.scannerResults` contains raw scanner evidence for that case.
- `cases[].run.judge` contains external judge output when `--judge` was used.

Use `--limit` and descriptive output paths to compare candidate changes:

```bash
clawscan benchmark clawhub-security-signals \
  --split eval_holdout \
  --limit 25 \
  --scanner clawscan-static \
  --output ./baseline-clawscan-benchmark.json
```

## Run Benchmarks In GitHub Actions

Use the **Run ClawScan Benchmark** workflow when you want a hosted artifact for
any supported benchmark/profile combination. It accepts the same core choices as
the CLI: benchmark ID, profile, optional config path, split, limit, offset, and
predictions output path.

Examples:

```text
benchmark_id: clawhub-security-signals
profile: clawhub
split: eval_holdout
limit: 10
```

```text
benchmark_id: SkillTrustBench
profile: clawhub
limit: 0
```

The workflow uploads the full benchmark artifact and writes a short summary to
the GitHub Actions run summary. For the built-in `clawhub` profile, configure
the required repository secrets for the scanner and judge path, including
`VIRUSTOTAL_API_KEY` and `OPENAI_API_KEY`.

The **SkillTrustBench Profile Gate** workflow is the maintainer-facing proposal
gate. It validates `proposals/<GHSA-ID>/clawscan.yml`, then delegates the actual
benchmark execution to **Run ClawScan Benchmark** and uses the uploaded artifact
to update the README benchmark block.

## Security Signals Leaderboard Submissions

The v1 Security Signals leaderboard submission path is GitHub PRs to this repo.
The Hugging Face Space is a display and convenience preview surface only; it
does not publish official rows.

1. Run ClawScan locally against the full ClawHub Security Signals split.
2. Put `metadata.json` and `predictions.jsonl` in a new
   `leaderboard/submissions/<run-id>/` directory.
3. Optionally include a full `artifact.json` from the benchmark run.
4. Open a PR. CI validates structure, recomputes metrics, and uploads a score
   preview artifact.
5. Optionally run the repository validation script locally if you are debugging
   a submission failure.
6. After review and merge, the post-merge publish workflow updates the private
   results dataset when Hugging Face credentials are configured.

Full benchmark run:

```bash
clawscan benchmark clawhub-security-signals \
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
    "dataset": "clawhub-security-signals",
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

Optional local validation while debugging:

```bash
scripts/validate-security-signals-submissions.sh leaderboard/submissions/<run-id>
```

The script runs the repository-only Security Signals validator. It rejects
duplicate case IDs, missing case IDs, unknown case IDs, invalid prediction
labels, mismatched dataset IDs, unsupported splits, and missing dataset revision
metadata. It recomputes loose non-clean metrics: `suspicious` and `malicious`
count as positive, and `clean` counts as negative.

Verification statuses:

| Status | Meaning |
| --- | --- |
| `artifact-validated` | CI validated submitted artifacts and recomputed score math. Scanner or judge execution was not rerun by OpenClaw. |
| `clawhub-production` | Row represents a ClawHub/OpenClaw-maintained production-style reference or baseline. |
| `openclaw-rerun` | Reserved for future rows rerun by OpenClaw-controlled infrastructure. |

The Gradio Space upload flow can validate and preview a `predictions.jsonl`
file before you open a PR. That upload does not publish results. Official
leaderboard rows come from reviewed and merged PR submissions.

## ClawHub Profile Proposals

Sensitive malicious ClawHub skill reports should go through GitHub private
vulnerability reporting. The public PR should contain only the candidate
profile config:

```text
proposals/<GHSA-ID>/clawscan.yml
```

That file must define a `clawhub` profile. Maintainers run the official
SkillTrustBench gate with:

```bash
clawscan benchmark SkillTrustBench \
  --config proposals/<GHSA-ID>/clawscan.yml \
  --profile clawhub \
  --output ./artifacts/skilltrustbench-candidate.json
```

The proposal profile shadows the built-in `clawhub` profile for that validation
run. Researchers should not edit the official bundled profile files in the
proposal PR. Maintainers port accepted behavior into
`internal/profiles/clawhub/clawscan.yml` after validation.

Operational source files:

- `leaderboard/submissions/README.md` documents the repo submission shape and
  seed rows.
- `leaderboard/results/README.md` documents the private results dataset and
  publish path.
- `leaderboard/space/README.md` documents the private Gradio Space scaffold and
  local smoke flow.
