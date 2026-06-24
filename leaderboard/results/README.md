# Security Signals Results Dataset

The authoritative accepted-results target is the private Hugging Face dataset:

```text
OpenClaw/clawhub-security-signals-results
```

This session could not verify that private dataset without Hugging Face
credentials. Unauthenticated API checks return `401 Invalid username or
password`, which is consistent with either a private dataset or inaccessible
resource from this environment.

Manual provisioning checklist:

1. Create a private Hugging Face dataset named
   `OpenClaw/clawhub-security-signals-results`.
2. Add a repository secret named `HF_TOKEN` with write access to that dataset.
3. Run the `Publish Security Signals results` workflow manually once, or merge a
   PR that changes `leaderboard/submissions/**`.
4. Confirm the dataset contains `results.jsonl`.

The publish path is intentionally separate from PR validation:

- PRs run `scripts/validate-security-signals-submissions.sh` without secrets.
- Post-merge publishing runs `scripts/publish-security-signals-results.sh`.
- Dry-run mode writes `dist/security-signals-results/results.jsonl` locally.

Each result row is JSONL with this shape:

```json
{
  "schemaVersion": "clawscan-security-signals-result-row-v1",
  "submissionId": "example-run",
  "submissionPath": "leaderboard/submissions/example-run",
  "metadataPath": "leaderboard/submissions/example-run/metadata.json",
  "predictionsPath": "leaderboard/submissions/example-run/predictions.jsonl",
  "artifactPath": "leaderboard/submissions/example-run/artifact.json",
  "benchmark": {
    "dataset": "OpenClaw/clawhub-security-signals",
    "split": "eval_holdout",
    "revision": "<hugging-face-dataset-sha>"
  },
  "system": {
    "name": "example-system",
    "role": "community"
  },
  "verificationStatus": "artifact-validated",
  "metrics": {
    "caseCount": 1,
    "truePositive": 0,
    "falsePositive": 0,
    "trueNegative": 1,
    "falseNegative": 0,
    "precision": 1,
    "recall": 1,
    "f1": 1,
    "falsePositiveRate": 0
  }
}
```
