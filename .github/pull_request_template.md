## Summary

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

- [ ] `go test -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `go run ./cmd/clawscan --help`
- [ ] Focused scanner/benchmark/manual proof:
- [ ] For ClawHub profile proposals: I opened the sensitive report through GitHub private vulnerability reporting, and this PR contains only `proposals/<GHSA-ID>/clawscan.yml`
- [ ] For ClawHub profile proposals: I did not edit `internal/profiles/builtin.yml`, `internal/profiles/clawhub/prompt.md`, or `internal/profiles/clawhub/output.schema.json`
- [ ] Docs site proof (`make docs-site`) or `N/A`:

## Notes

List any live scanner credentials, external services, benchmark datasets, or
release steps intentionally skipped.
