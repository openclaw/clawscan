# Repository Guidelines

## Project Purpose

ClawScan is a Go CLI for agent-skill security scanning. It runs scanner
adapters, preserves their raw JSON evidence, optionally invokes an external
judge harness, and supports benchmark/leaderboard workflows for comparing
scanner and judge setups.

Keep the public CLI general purpose. ClawHub parity helpers may exist in
separate commands, but do not add ClawHub-specific flags to `cmd/clawscan`.

## Project Structure

- `cmd/clawscan/` - public CLI entrypoint.
- `cmd/verify-clawhub-prompt/` - OpenClaw maintainer parity tooling, separate
  from the public CLI.
- `internal/runner/` - scanner adapters, artifact generation, judge execution,
  benchmark loading, and submission validation.
- `internal/profiles/` - built-in and project-local `.clawscan.yml` profile
  resolution.
- `internal/clawhubprompt/` - ClawHub prompt rendering parity support.
- `docs/` - public operator documentation and docs-site source.
- `leaderboard/` - Security Signals submissions, results, and Hugging Face
  Space support.
- `scripts/` - docs, release, and leaderboard helper scripts.
- `skills/clawscan-cli/` - Codex skill for using this CLI.
- `dist/` - generated release/docs artifacts. Do not hand-edit it.

## Development Commands

- `go test -count=1 ./...` - full Go test suite without cached results.
- `go vet ./...` - Go static checks.
- `go run ./cmd/clawscan --help` - inspect the public help output.
- `go run ./cmd/clawscan ./README.md --scanner clawscan-static --json` -
  secretless smoke test.
- `go run ./cmd/clawscan --benchmark --limit 1 --scanner clawscan-static --output /tmp/clawscan-benchmark-smoke.json`
  - benchmark smoke test.
- `make docs-site` - rebuild the generated docs site under `dist/docs-site`.
- `make release VERSION=v0.0.0-test` - build local release archives under
  `dist/`.

## Coding Style

- Use standard Go formatting. Run `gofmt` on touched Go files.
- Keep package boundaries small and boring; prefer targeted helpers over large
  cross-cutting abstractions.
- Keep scanner evidence raw. Scanner adapters should emit the upstream JSON or
  a small wrapper around skipped/error state, not a normalized policy summary.
- Add comments only for non-obvious contracts, such as secret redaction,
  artifact compatibility, or benchmark scoring semantics.

## Scanner And Judge Rules

- Public scanner IDs are part of the CLI surface. The built-in static scanner
  ID is `clawscan-static`; do not reintroduce `static`.
- Register built-in scanners through the scanner registry instead of adding
  one-off scanner switches.
- Scanner adapters should declare required environment variables up front so
  ClawScan can fail before doing partial work.
- Never add API-key CLI flags. Credentials belong in environment variables such
  as `VIRUSTOTAL_API_KEY`, `SNYK_TOKEN`, and `SOCKET_TOKEN`.
- Run artifacts must record only secret-safe env presence, such as `present` or
  `missing`, never secret values.
- `--judge` is an external harness command. Do not add a model-provider
  framework to ClawScan unless the product direction changes.
- Judge placeholders and prompt interpolation must fail clearly when they
  reference a scanner that was not requested.

## Profiles And Benchmarks

- Built-in profiles live in `internal/profiles/builtin.yml`.
- Project-local `.clawscan.yml` / `.clawscan.yaml` files may shadow built-ins.
  CLI flags override profile values for a single run.
- Select the ClawHub production profile explicitly with `--profile clawhub`.
  `--config <path>` without `--profile` runs every profile in that config.
- Supported benchmark verdicts are `clean`, `suspicious`, and `malicious`.
- OpenClaw Security Signals predictions use `predictions.jsonl`; keep that file
  lightweight and secret-free.

## Verification Expectations

- For Go behavior changes, run focused tests plus `go test -count=1 ./...` and
  `go vet ./...`.
- For docs/help changes, run `make docs-site` when generated docs can change.
- For scanner adapters, add fixture-backed tests and use live API smoke tests
  only when credentials are already available. Do not print secrets.
- For leaderboard/submission changes, validate the relevant shell/Python paths
  and run `scripts/validate-security-signals-submissions.sh` on a representative
  fixture when possible.

## Commit And Release Notes

- Use conventional commit messages.
- Keep generated `dist/` changes out of ordinary feature commits unless the
  task is release-packaging proof.
- Releases are tag-driven through the GitHub release workflow. Local release
  archives should match `make release VERSION=<version>`.
