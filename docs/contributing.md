# Contributing

Contributors usually work in one of four lanes:

- ordinary repo maintenance, docs, tests, and release plumbing
- scanner adapters
- benchmark and leaderboard workflow improvements
- ClawHub scan improvements that should remain visible through ClawScan

The public CLI should stay useful outside OpenClaw. ClawHub-specific parity and
maintenance helpers belong in separate commands or repo scripts, not in
ClawScan's public flag surface.

## Local Setup

Install Go 1.22 or newer, then run the baseline checks from the repository
root:

```bash
go test -count=1 ./...
go vet ./...
make docs-site
go run ./cmd/clawscan --help
```

The secretless scanner smoke test is:

```bash
go run ./cmd/clawscan ./README.md \
  --scanner clawscan-static \
  --json
```

Use live scanner credentials only when you already have them. Credentials must
come from environment variables such as `VIRUSTOTAL_API_KEY`, `SNYK_TOKEN`,
`SOCKET_TOKEN`, `AIG_BASE_URL`, `AIG_MODEL`, and `AIG_MODEL_API_KEY`.

## Validation Matrix

| Change type | Expected validation |
| --- | --- |
| Docs only | `make docs-site` |
| Public help or CLI behavior | `go test -count=1 ./...`, `go vet ./...`, `go run ./cmd/clawscan --help` |
| Scanner adapter | Focused fixture-backed tests, `go test -count=1 ./...`, `go vet ./...`, docs/help updates |
| Benchmark behavior | Focused benchmark tests, `go test -count=1 ./...`, a `--benchmark --limit 1` smoke when practical |
| Leaderboard submission plumbing | Relevant script test or repo validator run, plus CI |

CI owns normal Security Signals submission validation for PRs. If you are
debugging locally, run:

```bash
scripts/validate-security-signals-submissions.sh leaderboard/submissions/<run-id>
```

## Review Expectations

Keep PRs reviewable:

- one PR should cover one issue or topic
- scanner evidence should stay raw unless an artifact contract explicitly says
  otherwise
- new required credentials must be validated up front and recorded only as
  `present` or `missing`
- benchmark docs should treat `clawscan-benchmark.json` as the primary local
  result artifact
- generated `dist/` docs-site output should stay out of ordinary docs commits

Use conventional commit messages and include the exact validation commands you
ran in the issue or PR handoff.

## Deeper Guides

- [Scanners](scanners.md) explains the built-in scanner adapter contract.
- [Benchmarks](benchmarks.md) explains local benchmark artifacts and scoring.
- [Improving ClawHub scans](improving-clawhub-scans.md) describes the
  ClawHub-focused improvement loop.
- [Artifacts](artifacts.md) documents the JSON shapes reviewers should inspect.
- The repository `SECURITY.md` explains private vulnerability reporting.
