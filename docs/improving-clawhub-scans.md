# Improving ClawHub Scans

ClawScan exists partly so ClawHub's skill-scanning setup can be inspected and
improved in public. The improvement loop should still use the general-purpose
`clawscan` command: run the ClawHub-style profile, evaluate it on the OpenClaw
Security Signals benchmark, compare the `clawscan-benchmark.json` evidence, and
propose a targeted change.

Do not add ClawHub-specific flags to the public CLI. If exact ClawHub parity
needs a maintainer helper, keep that helper outside `cmd/clawscan`.

## 1. Run The ClawHub Profile

From a repository or test fixture with skills under `./skills/<name>/SKILL.md`:

```bash
clawscan \
  --profile clawhub \
  --output ./clawscan-run.json
```

For one explicit skill target:

```bash
clawscan ./my-skill \
  --profile clawhub \
  --output ./clawscan-run.json
```

The built-in `clawhub` profile runs the generic scanner suite:
`skillspector`, `virustotal`, and `clawscan-static`. It does not bundle
ClawHub's production-only judge prompt or deployment settings. Those belong in
the ClawHub project configuration or maintainer tooling.

## 2. Run The Security Signals Benchmark

Start small while iterating:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 10 \
  --profile clawhub \
  --output ./clawscan-benchmark.json
```

Use `--limit 0` when you intentionally want the full split:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 0 \
  --profile clawhub \
  --output ./clawscan-benchmark.json
```

The benchmark artifact is the primary result to inspect. For the OpenClaw
benchmark, ClawScan may also write `predictions.jsonl` for leaderboard and CI
submission plumbing, but that file is derived from the richer benchmark
artifact.

## 3. Compare Results

Read the benchmark summary first:

- `summary.caseCount` shows how many cases ran
- `summary.expectedVerdicts` shows the label mix
- `summary.scannerStatuses` shows completed, skipped, and errored scanner
  counts
- each `cases[].evaluation` entry shows whether the prediction was correct,
  incorrect, abstained, unscorable, or errored when ClawScan can score it

Then inspect individual cases:

- `cases[].expected` explains the benchmark label and context
- `cases[].run.scannerResults` contains each scanner's raw evidence
- `cases[].run.judge` contains the external judge result when configured

For quick local comparison, save artifacts with descriptive names:

```bash
clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 50 \
  --profile clawhub \
  --output ./baseline-clawscan-benchmark.json

clawscan \
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 50 \
  --scanner clawscan-static \
  --output ./candidate-clawscan-benchmark.json
```

## 4. Propose A Focused Improvement

Good ClawHub scan improvements usually fit one of these buckets:

- scanner adapter behavior, such as better target handling or clearer skipped
  results
- built-in profile composition, such as adding or removing a general-purpose
  scanner from a profile
- judge prompt or schema changes in the project that owns the judge harness
- benchmark fixture improvements that make a missed malicious skill or false
  positive reproducible

Keep the proposal narrow. Include the before/after benchmark artifacts, the
command lines used to produce them, and the specific cases that improved or
regressed.

## 5. Flow Back Into ClawHub

Accepted changes can reach ClawHub through different paths:

- general scanner adapter improvements land in this repo and become available
  to any ClawScan user
- built-in profile changes land here only when they remain general-purpose
- ClawHub-specific judge prompts, schemas, model settings, or deployment wiring
  land in the ClawHub repo
- benchmark updates land in the Security Signals dataset/submission workflow
  when they are about evaluation coverage rather than scanner runtime behavior

That split keeps ClawScan open and benchmarkable while still giving ClawHub a
clear path to adopt better scanning behavior.
