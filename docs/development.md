# Development

## Local Checks

```bash
go test ./...
go vet ./...
make docs-site
```

Contributor setup, validation expectations, and review conventions live in
[Contributing](contributing.md).

## Local Smoke Tests

The static scanner needs no secrets:

```bash
go run ./cmd/clawscan ./README.md \
  --scanner clawscan-static \
  --output /tmp/clawscan-smoke.json
```

Benchmark smoke:

```bash
go run ./cmd/clawscan \
  --benchmark \
  --limit 1 \
  --scanner clawscan-static \
  --output /tmp/clawscan-benchmark-smoke.json
```

Docker runtime smoke:

```bash
docker build -t clawscan-runtime:dev docker/clawscan-runtime
docker run --rm clawscan-runtime:dev codex --help
docker run --rm clawscan-runtime:dev claude --help
docker run --rm clawscan-runtime:dev skillspector --help
```

## Runtime Tool Updates

The runtime image pins scanner and judge-tool versions in
`docker/clawscan-runtime/Dockerfile`. Do not float these installs to `latest`:
runtime tool changes can alter scanner output, judge behavior, runtime, and
failure rate.

The `Runtime Tool Updates` workflow runs monthly, updates the pinned versions,
builds the candidate image, runs CLI smoke checks, and opens a PR. That PR must
not be auto-merged from smoke checks alone.

Before merging a runtime-tool update PR, run a benchmark comparison from the PR
branch and attach the result artifacts or summary to the PR:

```bash
docker build -t clawscan-runtime:candidate docker/clawscan-runtime

CLAWSCAN_SANDBOX_IMAGE=clawscan-runtime:candidate \
go run ./cmd/clawscan \
  --benchmark SkillTrustBench \
  --scanner clawscan-static \
  --output /tmp/clawscan-skilltrustbench-candidate.json
```

For ClawHub-affecting changes, also compare the OpenClaw Security Signals
benchmark or the relevant ClawHub profile benchmark path. Explain any verdict
drift, scanner failures, or runtime regression before merge.

## Docs Site

The docs site is generated from Markdown in `docs/`:

```bash
make docs-site
open dist/docs-site/index.html
```

The GitHub Pages workflow builds the site on pushes to `main` when docs, the
builder script, or the workflow changes.

## Release Packaging

Release artifacts are built with Go only:

```bash
make release VERSION=v0.1.0
```

The release target writes archives to `dist/`:

- `clawscan_<version>_darwin_amd64.tar.gz`
- `clawscan_<version>_darwin_arm64.tar.gz`
- `clawscan_<version>_linux_amd64.tar.gz`
- `clawscan_<version>_linux_arm64.tar.gz`
- `clawscan_<version>_windows_amd64.zip`
- `checksums.txt`

Tagged `v*` releases publish those artifacts to GitHub Releases. After the
GitHub Release is published, the release workflow dispatches
`openclaw/homebrew-tap` to update `Formula/clawscan.rb` from the same release
archives. The tap update requires a `HOMEBREW_TAP_TOKEN` or
`HOMEBREW_TAP_GITHUB_TOKEN` secret with workflow and push access to the tap
repository. If that secret is missing, release artifacts are still published and
the Homebrew update is skipped with a workflow warning.

Release operation notes live in [Releasing](releasing.md).

## ClawHub Parity Tooling

ClawScan is general purpose, but OpenClaw also uses it to make ClawHub's
production scan path inspectable. The internal verifier compares the Go-rendered
prompt against the current ClawHub worker output and records byte-level hashes.

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /path/to/clawhub \
  --out /tmp/clawhub-prompt-parity-proof-go.json
```

Use the exporter flags when ClawHub's production prompt or output schema changes
and the baked-in `clawhub` profile assets need to be refreshed:

```bash
go run ./cmd/verify-clawhub-prompt \
  --clawhub-dir /path/to/clawhub \
  --out-prompt internal/profiles/clawhub/prompt.md \
  --out-output-schema internal/profiles/clawhub/output.schema.json
```

ClawHub-specific proof helpers live outside the public `clawscan` command so
the main CLI stays useful for non-ClawHub users, while the built-in `clawhub`
profile remains the public recipe that ClawHub runs.

For the public ClawHub improvement loop, see
[Improving ClawHub scans](improving-clawhub-scans.md).
