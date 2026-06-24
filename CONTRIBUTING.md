# Contributing to ClawScan

Thanks for helping improve ClawScan. This repo is a Go CLI for agent-skill
security scanning, so contributions should keep the public command general
purpose, evidence-first, and safe to run in ordinary developer and CI
environments.

## Setup

Prerequisites:

- Go 1.22 or newer.
- Node.js/npm for scanner adapters that shell out through `npx`.
- `make` for docs and release helper targets.
- Optional scanner credentials in environment variables, never CLI flags.

From a checkout:

```bash
go test -count=1 ./...
go vet ./...
make docs-site
go run ./cmd/clawscan --help
go run ./cmd/clawscan ./README.md --scanner clawscan-static --json
```

Use fixture-backed scanner results when credentials or live upstream services
are not available:

```bash
go run ./cmd/clawscan ./my-skill \
  --scanner skillspector \
  --scanner-result skillspector=./fixtures/skillspector.json \
  --json
```

## What To Change

Keep pull requests focused on one behavior, adapter, documentation topic, or
benchmark workflow. Avoid bundling scanner behavior, artifact schema changes,
profile changes, and docs cleanup into one PR unless they are inseparable.

Public CLI flags must stay general purpose. ClawHub parity helpers can live in
separate maintainer commands, but do not add ClawHub-specific flags to
`cmd/clawscan`.

Good starting points:

- [Contributing guide](docs/contributing.md)
- [Adding scanner adapters](docs/scanners.md#adding-a-built-in-scanner-adapter)
- [Running benchmarks](docs/benchmarks.md)
- [Improving ClawHub scans](docs/improving-clawhub-scans.md)
- [Development commands](docs/development.md)
- [Security policy](SECURITY.md)

## Validation

For documentation-only changes, run:

```bash
make docs-site
```

For Go behavior, scanner adapters, profiles, artifacts, or help output, run:

```bash
go test -count=1 ./...
go vet ./...
go run ./cmd/clawscan --help
```

For benchmark or leaderboard submission plumbing, CI validates changed
submission directories. Maintainers can also run the repository validation
script while debugging:

```bash
scripts/validate-security-signals-submissions.sh leaderboard/submissions/<run-id>
```

## Commit And Review Expectations

- Use conventional commit messages.
- Keep generated `dist/` changes out of ordinary feature and docs commits.
- Mention the exact validation commands you ran in the PR or issue handoff.
- Do not include secrets, tokens, or unredacted scanner output in commits,
  artifacts, issues, or pull requests.
- Prefer small, reviewable changes with fixture-backed tests for scanner
  behavior.

## Security Reports

Report vulnerabilities privately through this repository's GitHub private
vulnerability reporting flow. If you are unsure where to route a report, email
security@openclaw.ai. See [SECURITY.md](SECURITY.md) for the full policy and
what to include.
