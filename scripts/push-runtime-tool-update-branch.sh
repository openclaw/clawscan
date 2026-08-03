#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <remote> <branch>" >&2
  exit 64
fi

remote="$1"
branch="$2"
remote_ref="refs/heads/${branch}"
tracking_ref="refs/remotes/${remote}/${branch}"

git remote get-url "$remote" >/dev/null
git check-ref-format --branch "$branch" >/dev/null
git check-ref-format "$tracking_ref" >/dev/null
git rev-parse --verify "HEAD^{commit}" >/dev/null

set +e
remote_output="$(git ls-remote --exit-code --heads "$remote" "$remote_ref")"
remote_status=$?
set -e

case "$remote_status" in
  0)
    if [[ "$remote_output" == *$'\n'* ]]; then
      echo "expected one remote ref for ${remote_ref}" >&2
      exit 1
    fi
    read -r observed_oid observed_ref extra <<< "$remote_output"
    if [[ ! "$observed_oid" =~ ^[0-9a-f]{40}$ || "$observed_ref" != "$remote_ref" || -n "${extra:-}" ]]; then
      echo "invalid remote ref response for ${remote_ref}" >&2
      exit 1
    fi

    git fetch --no-tags --depth=1 "$remote" "+${remote_ref}:${tracking_ref}"
    fetched_oid="$(git rev-parse --verify "${tracking_ref}^{commit}")"
    if [[ "$fetched_oid" != "$observed_oid" ]]; then
      echo "${remote_ref} changed while its lease was being prepared" >&2
      exit 1
    fi
    expected_oid="$observed_oid"
    ;;
  2)
    expected_oid=""
    ;;
  *)
    echo "failed to inspect ${remote_ref} on ${remote}" >&2
    exit "$remote_status"
    ;;
esac

# Rebuild the standing automation branch only if its observed tip is unchanged.
git push \
  --force-with-lease="${remote_ref}:${expected_oid}" \
  "$remote" \
  "HEAD:${remote_ref}"
