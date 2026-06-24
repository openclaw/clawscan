#!/usr/bin/env bash
set -euo pipefail

mode="dry-run"
submission_root="leaderboard/submissions"
output_path="dist/security-signals-results/results.jsonl"
results_dataset="${HF_RESULTS_DATASET:-OpenClaw/clawhub-security-signals-results}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      mode="dry-run"
      shift
      ;;
    --publish)
      mode="publish"
      shift
      ;;
    --root)
      if [ "$#" -lt 2 ]; then
        echo "Expected --root value" >&2
        exit 1
      fi
      submission_root="$2"
      shift 2
      ;;
    --output)
      if [ "$#" -lt 2 ]; then
        echo "Expected --output value" >&2
        exit 1
      fi
      output_path="$2"
      shift 2
      ;;
    --dataset)
      if [ "$#" -lt 2 ]; then
        echo "Expected --dataset value" >&2
        exit 1
      fi
      results_dataset="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'USAGE'
Usage: scripts/publish-security-signals-results.sh [--dry-run|--publish] [--root <dir>] [--output <path>] [--dataset <repo>]

Builds the Security Signals results dataset payload from accepted submission
directories. Dry-run mode writes the JSONL payload locally. Publish mode uploads
that payload to the private Hugging Face dataset with huggingface-cli.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

validator_cmd=(go run ./scripts/validate-security-signals-submission.go)
if [ -n "${CLAWSCAN_VALIDATE_SUBMISSION_CMD:-}" ]; then
  read -r -a validator_cmd <<<"${CLAWSCAN_VALIDATE_SUBMISSION_CMD}"
fi

submission_dirs=()
if [ -d "$submission_root" ]; then
  while IFS= read -r -d '' file; do
    submission_dirs+=("$(dirname "$file")")
  done < <(find "$submission_root" -mindepth 2 -maxdepth 2 -name metadata.json -print0 | sort -z)
fi

mkdir -p "$(dirname "$output_path")"
: >"$output_path"

if [ "${#submission_dirs[@]}" -eq 0 ]; then
  echo "No Security Signals submissions found under $submission_root."
else
  for dir in "${submission_dirs[@]}"; do
    if [ ! -f "$dir/predictions.jsonl" ]; then
      echo "Missing $dir/predictions.jsonl" >&2
      exit 1
    fi
    score_json="$("${validator_cmd[@]}" "$dir" --json)"
    SCORE_JSON="$score_json" SUBMISSION_DIR="$dir" python3 - <<'PY' >>"$output_path"
import json
import os
from pathlib import Path

score = json.loads(os.environ["SCORE_JSON"])
submission_dir = Path(os.environ["SUBMISSION_DIR"])
row = {
    "schemaVersion": "clawscan-security-signals-result-row-v1",
    "submissionId": submission_dir.name,
    "submissionPath": str(submission_dir),
    "metadataPath": str(submission_dir / "metadata.json"),
    "predictionsPath": str(submission_dir / "predictions.jsonl"),
    "artifactPath": str(submission_dir / "artifact.json") if (submission_dir / "artifact.json").exists() else "",
    "benchmark": score.get("benchmark", {}),
    "system": score.get("system", {}),
    "verificationStatus": score.get("verificationStatus", ""),
    "metrics": score.get("metrics", {}),
}
print(json.dumps(row, separators=(",", ":"), sort_keys=True))
PY
  done
fi

echo "Wrote $output_path"

if [ "$mode" = "dry-run" ]; then
  echo "Dry run only; not publishing to $results_dataset."
  exit 0
fi

if [ -z "${HF_TOKEN:-}" ]; then
  echo "HF_TOKEN is required for --publish" >&2
  exit 1
fi
if ! command -v huggingface-cli >/dev/null 2>&1; then
  echo "huggingface-cli is required for --publish. Install with: python -m pip install huggingface_hub" >&2
  exit 1
fi

huggingface-cli upload "$results_dataset" "$output_path" results.jsonl --repo-type dataset --token "$HF_TOKEN"
