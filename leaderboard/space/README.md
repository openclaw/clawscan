---
title: ClawHub Security Signals Leaderboard
sdk: gradio
app_file: app.py
pinned: false
---

# Security Signals Leaderboard Space

This is the source scaffold for the private Hugging Face Space:

```text
OpenClaw/clawhub-security-signals-leaderboard
```

The Space is a read-only presentation and validation surface. Official
submissions still go through GitHub PRs in `openclaw/clawscan`; the Space must
not write to the official results dataset in v1.

Local smoke:

```bash
python3 leaderboard/space/app.py --smoke
```

Run locally with Gradio installed:

```bash
python3 leaderboard/space/app.py
```

By default, the app reads `leaderboard/space/fixtures/results.jsonl`. On Hugging
Face, configure `SECURITY_SIGNALS_RESULTS_REPO` to
`OpenClaw/clawhub-security-signals-results` so the app downloads
`results.jsonl` from the private results dataset.

The upload preview uses `leaderboard/space/fixtures/expected_eval_holdout.jsonl`
by default. Set `SECURITY_SIGNALS_EXPECTED_PATH` if the expected-label fixture is
mounted elsewhere.

Manual provisioning checklist:

1. Create a private Gradio Space named
   `OpenClaw/clawhub-security-signals-leaderboard`.
2. Add this directory's files to the Space repository.
3. Configure Space access to the private results dataset.
4. Set `SECURITY_SIGNALS_RESULTS_REPO=OpenClaw/clawhub-security-signals-results`.
5. Smoke locally with the fixture before relying on hosted runtime state.

Upload validation is intentionally non-authoritative. It reports schema and case
coverage errors and computes a loose non-clean score preview, but official
leaderboard rows still require a GitHub PR.
