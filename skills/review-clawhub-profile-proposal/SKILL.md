---
name: review-clawhub-profile-proposal
description: >-
  Use when an OpenClaw maintainer or owner is reviewing a ClawHub malicious-skill
  profile proposal PR: checking `proposals/<GHSA-ID>/clawscan.yml`, reading the
  private vulnerability context without leaking it, running the SkillTrustBench
  Profile Gate or equivalent local benchmark, updating the accepted baseline,
  and promoting an accepted candidate into `internal/profiles/clawhub/clawscan.yml`.
---

# Review ClawHub Profile Proposal

## Overview

Use this owner-side workflow for a public PR that proposes a candidate ClawHub
profile at `proposals/<GHSA-ID>/clawscan.yml` after a private vulnerability
report. The goal is to validate the candidate, keep sensitive details private,
and, if accepted, promote the public profile behavior into the bundled
`internal/profiles/clawhub/clawscan.yml`.

## Safety Boundary

- Treat the GitHub private vulnerability report as the source for sensitive
  malicious skill details.
- Do not paste live exploit details, private report text, private artifacts, or
  suspicious skill payloads into public PR comments, public docs, commit
  messages, or committed baseline summaries.
- The public proposal PR should start with only
  `proposals/<GHSA-ID>/clawscan.yml`. Do not trust it until reviewed.
- Do not run the suspicious skill. ClawScan scans skill files as data; it should
  not execute the skill's behavior.
- Do not promote a candidate unless the private report, proposal diff, and
  benchmark proof all line up.

## Review Workflow

1. Read the current repo and PR state.

   - Check `git status --short --branch` before editing.
   - Fetch the PR branch and inspect the changed files.
   - Confirm the public PR initially contains only
     `proposals/<GHSA-ID>/clawscan.yml` plus any baseline summary commit
     produced by the maintainer gate.
   - Confirm the proposal file defines a `clawhub` profile.
   - Confirm the proposal does not edit official bundled profile files yet:
     `internal/profiles/clawhub/clawscan.yml`,
     `internal/profiles/clawhub/prompt.md`, or
     `internal/profiles/clawhub/output.schema.json`.

2. Read the private report privately.

   Use the private vulnerability report only to understand:

   - what malicious behavior must be caught
   - why the current built-in `clawhub` profile misses or under-detects it
   - what evidence should be preserved privately
   - whether any proposal text or config comments leak sensitive details

   Keep public comments high-level, such as "validated against the private
   report" or "needs private-case follow-up"; do not quote private details.

3. Validate the candidate profile.

   Prefer the manual GitHub Actions workflow when available:

   ```text
   SkillTrustBench Profile Gate
   ```

   Dispatch it with the PR number and proposal path. It should run:

   ```bash
   clawscan benchmark SkillTrustBench \
     --ids https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results/resolve/main/data/evaluation_subset_10pct.jsonl \
     --config proposals/<GHSA-ID>/clawscan.yml \
     --profile clawhub \
     --output ./artifacts/skilltrustbench-candidate.json
   ```

   If running locally, use the same command. The `--ids` source is the public
   SkillTrustBench leaderboard subset and is mutually exclusive with `--limit`
   and `--offset`.

4. Review the benchmark artifact.

   Check:

   - the artifact is full JSON and preserved as a workflow artifact or private
     maintainer artifact
   - `benchmark.id` is `cuhk-zhuque/SkillTrustBench`
   - `benchmark.split` is `benchmark`
   - `benchmark.idsCount` is `556`
   - `benchmark.idsSha256` matches the planned subset hash
     `903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2`
   - scanner and judge statuses are acceptable
   - evaluation metrics are not an unacceptable regression
   - the candidate catches the private reported behavior when private proof is
     available

5. Update the accepted baseline summary.

   Use the repo script so the compact baseline is generated from the full
   candidate artifact:

   ```bash
   go run ./scripts/update-skilltrustbench-baseline \
     --artifact ./artifacts/skilltrustbench-candidate.json \
     --output benchmarks/skilltrustbench-leaderboard-10pct/clawhub-baseline.json \
     --profile clawhub \
     --profile-source proposals/<GHSA-ID>/clawscan.yml \
     --subset-case-ids-sha256 903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2 \
     --workflow-url <workflow-url>
   ```

   If the PR merges, that committed file is the latest accepted baseline for
   the bundled `clawhub` profile. The script fails if the candidate artifact's
   selected-ID hash does not match the planned subset. No post-merge rerun is
   required.

6. Decide.

   If rejected:

   - leave a public PR comment with non-sensitive reasons
   - keep details that identify the malicious payload in the private report
   - do not edit official bundled profile files

   If accepted:

   - promote the accepted public `clawhub` profile behavior into
     `internal/profiles/clawhub/clawscan.yml`
   - keep `benchmarks/skilltrustbench-leaderboard-10pct/clawhub-baseline.json`
     updated from the candidate artifact in the same PR
   - preserve or remove `proposals/<GHSA-ID>/clawscan.yml` according to the
     issue/PR instruction; default to preserving it as public proposal trail
     unless the maintainer explicitly chooses to remove it
   - keep prompt/schema changes maintainer-owned; edit
     `internal/profiles/clawhub/prompt.md` or
     `internal/profiles/clawhub/output.schema.json` only when that is the
     accepted change

7. Verify the promoted built-in profile.

   Run at least:

   ```bash
   go test -count=1 ./...
   go vet ./...
   go run ./cmd/clawscan profiles -v
   go run ./cmd/clawscan --help
   ```

   For benchmark proof after promotion, run:

   ```bash
   clawscan benchmark SkillTrustBench \
     --ids https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results/resolve/main/data/evaluation_subset_10pct.jsonl \
     --profile clawhub \
     --output ./artifacts/skilltrustbench-clawhub.json
   ```

   Use a smaller proof only when explicitly accepted; the official gate uses
   the subset ID source above.

8. Update the PR.

   - Push the promotion commit to the PR branch if that is the chosen review
     path.
   - Keep the PR body/comments free of private exploit details.
   - Add proof with commands, artifact links, and residual risk.

## Promotion Patch Shape

The maintainer promotion commit usually touches:

```text
internal/profiles/clawhub/clawscan.yml
benchmarks/skilltrustbench-leaderboard-10pct/clawhub-baseline.json
```

It may also touch:

```text
internal/profiles/clawhub/prompt.md
internal/profiles/clawhub/output.schema.json
docs/
tests
```

Do not include private artifacts, malicious payload details, or generated
`dist/` output in ordinary promotion commits unless the issue explicitly asks
for them.

## Handoff Shape

End with:

- verdict: accepted, rejected, or blocked
- proposal path and PR/ref reviewed
- private report checked, without sensitive details
- benchmark command and artifact location
- baseline summary update status
- bundled profile files changed
- exact verification commands and results
- commit SHA or reason no commit was created
- residual risk and next owner action
