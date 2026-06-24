# Security Signals Leaderboard Submissions

This directory is the v1 GitHub PR submission path for Security Signals
leaderboard runs.

Each submission lives in its own directory:

```text
leaderboard/submissions/<run-id>/
  metadata.json
  predictions.jsonl
  artifact.json        # optional full ClawScan benchmark artifact
```

`metadata.json` declares the benchmark identity and run provenance:

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

`predictions.jsonl` is the lightweight score input. It must contain exactly one
row for each case in the declared split:

```json
{"id":"case-id-1","prediction":"clean"}
{"id":"case-id-2","prediction":"suspicious"}
{"id":"case-id-3","prediction":"malicious"}
```

Validate a submission locally before opening a PR:

```bash
go run ./cmd/clawscan validate-submission leaderboard/submissions/<run-id>
```

CI validates changed submission directories with the same ClawScan validator,
recomputes loose non-clean metrics, and uploads JSON score previews as workflow
artifacts. The PR path is artifact-validated: CI verifies structure and score
math, but it does not rerun expensive scanners or model judges.
