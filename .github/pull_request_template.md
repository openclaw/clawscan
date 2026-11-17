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
In 1-3 plain-language sentences, explain the affected task, what fails or is
missing, and why it matters. Include the trigger when known. Do not invent a bug
for other changes. These examples illustrate wording, not an observed defect:
Good: "Operators cannot tell which scanner failed to finish, so they cannot distinguish
an incomplete scan from a clean result."
Bad: "Updates an internal handler and adds a missing check."
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
