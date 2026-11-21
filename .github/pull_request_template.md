<!--
Write the title and opening problem statement for skill-scanning operators.
Name the affected task and the symptom or outcome, not only the implementation.
Good: fix: explain which scanner did not finish
Bad: fix: update the scanner status mapping
For internal-only work, name the actual developer or operator workflow affected;
do not invent an end-user benefit.
-->

## Summary

<!--
In 1–3 plain sentences, say who is affected, what happens today, and why it
matters to them. For a bug, name the trigger if known. For a feature or internal
work, describe the need in the actual workflow without inventing harm.
Could a reader understand the problem without knowing your proposed fix?

Good: "Background checks can use up a new user's model allowance before they've
asked the assistant to monitor anything."
Bad: "Turn off periodic checks on fresh installs."
-->

- What changed:
- Why:

## Scope

- [ ] CLI behavior
- [ ] Scanner adapter
- [ ] Judge/profile/benchmark behavior
- [ ] ClawHub profile proposal at `proposals/<GHSA-ID>/clawscan.yml`
- [ ] Docs only
- [ ] Release/CI/repo automation

## Security / Trust Impact

- [ ] No security/trust impact
- [ ] Security/trust impact explained

Explain any effect on scanner execution, judge commands, prompt/schema handling,
secret redaction, benchmark submissions, or generated artifacts.

## Verification

<!--
Lead with the behavior checked and the observed result in plain language, then
include exact commands and supporting evidence. Put long logs and commit hashes
in links or optional <details>. Keep meaningful gaps, risks, and required
actions visible; do not make readers decode commands to learn what was verified.
-->

- [ ] `go test -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `go run ./cmd/clawscan --help`
- [ ] Focused scanner/benchmark/manual proof:
- [ ] For ClawHub profile proposals: I opened the sensitive report through GitHub private vulnerability reporting, and this PR contains only `proposals/<GHSA-ID>/clawscan.yml`
- [ ] For ClawHub profile proposals: I did not edit official bundled profile files under `internal/profiles/`
- [ ] Docs site proof (`make docs-site`) or `N/A`:

## Notes

List any live scanner credentials, external services, benchmark datasets, or
release steps intentionally skipped.
