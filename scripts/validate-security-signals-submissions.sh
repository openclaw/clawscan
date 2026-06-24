#!/usr/bin/env bash
set -euo pipefail

submission_root="leaderboard/submissions"
validate_all=false
declare -a explicit_dirs=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --all)
      validate_all=true
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
    --help|-h)
      cat <<'USAGE'
Usage: scripts/validate-security-signals-submissions.sh [--all] [--root <dir>] [submission-dir...]

Validates Security Signals leaderboard submissions with:

  go run ./scripts/validate-security-signals-submission.go <submission-dir>

By default, pull-request runs validate changed submission directories under
leaderboard/submissions. Outside pull requests, the script validates all
submission directories that contain metadata.json or predictions.jsonl.
USAGE
      exit 0
      ;;
    -*)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
    *)
      explicit_dirs+=("$1")
      shift
      ;;
  esac
done

validator_cmd=(go run ./scripts/validate-security-signals-submission.go)
if [ -n "${CLAWSCAN_VALIDATE_SUBMISSION_CMD:-}" ]; then
  # Test seam for local/script tests. CI uses the real repository validator above.
  read -r -a validator_cmd <<<"${CLAWSCAN_VALIDATE_SUBMISSION_CMD}"
fi

score_dir="${CLAWSCAN_SUBMISSION_SCORE_DIR:-dist/security-signals-submission-scores}"
mkdir -p "$score_dir"

submission_dirs=()

add_submission_dir() {
  local dir="$1"
  if [ -z "$dir" ]; then
    return
  fi
  if [ "${#submission_dirs[@]}" -gt 0 ]; then
    for existing in "${submission_dirs[@]}"; do
      if [ "$existing" = "$dir" ]; then
        return
      fi
    done
  fi
  submission_dirs+=("$dir")
}

find_all_submission_dirs() {
  if [ ! -d "$submission_root" ]; then
    return
  fi
  while IFS= read -r -d '' file; do
    add_submission_dir "$(dirname "$file")"
  done < <(find "$submission_root" -mindepth 2 -maxdepth 2 \( -name metadata.json -o -name predictions.jsonl \) -print0 | sort -z)
}

find_changed_submission_dirs() {
  local base_ref="${GITHUB_BASE_REF:-}"
  if [ -z "$base_ref" ]; then
    find_all_submission_dirs
    return
  fi
  git fetch --no-tags --depth=1 origin "$base_ref" >/dev/null 2>&1 || true
  local base="origin/$base_ref"
  if ! git rev-parse --verify "$base" >/dev/null 2>&1; then
    find_all_submission_dirs
    return
  fi
  while IFS= read -r file; do
    case "$file" in
      "$submission_root"/*/*)
        add_submission_dir "$(dirname "$file")"
        ;;
    esac
  done < <(git diff --name-only "$base"...HEAD -- "$submission_root" || true)
}

if [ "${#explicit_dirs[@]}" -gt 0 ]; then
  for dir in "${explicit_dirs[@]}"; do
    add_submission_dir "$dir"
  done
elif [ "$validate_all" = true ]; then
  find_all_submission_dirs
else
  find_changed_submission_dirs
fi

if [ "${#submission_dirs[@]}" -eq 0 ]; then
  echo "No Security Signals submissions changed."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "## Security Signals submissions"
      echo
      echo "No Security Signals submissions changed."
    } >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Security Signals submissions"
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi

for dir in "${submission_dirs[@]}"; do
  if [ ! -f "$dir/metadata.json" ]; then
    echo "Missing $dir/metadata.json" >&2
    exit 1
  fi
  if [ ! -f "$dir/predictions.jsonl" ]; then
    echo "Missing $dir/predictions.jsonl" >&2
    exit 1
  fi

  safe_name="$(echo "$dir" | tr '/ ' '__')"
  score_path="$score_dir/$safe_name.score.json"
  echo "Validating $dir"
  "${validator_cmd[@]}" "$dir" --json >"$score_path"
  summary="$("${validator_cmd[@]}" "$dir")"
  echo "$summary"

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### $dir"
      echo
      echo '```text'
      echo "$summary"
      echo '```'
      echo
      echo "Score JSON: \`$score_path\`"
      echo
    } >>"$GITHUB_STEP_SUMMARY"
  fi
done
