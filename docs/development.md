# Development

## Local Checks

```bash
go test ./...
go vet ./...
make docs-site
```

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
  --benchmark OpenClaw/clawhub-security-signals \
  --split eval_holdout \
  --limit 1 \
  --scanner clawscan-static \
  --output /tmp/clawscan-benchmark-smoke.json
```

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

ClawHub-specific proof helpers live outside the public `clawscan` command so
the main CLI stays useful for non-ClawHub users.
