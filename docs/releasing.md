# Releasing ClawScan

This playbook follows the OpenClaw Go CLI release pattern: GitHub release
archives are the source of truth, and `openclaw/homebrew-tap` provides the easy
install path.

## Release Channels

- Homebrew: `brew install openclaw/tap/clawscan`
- GitHub Releases: macOS, Linux, and Windows archives plus `checksums.txt`
- Go module: `go install github.com/openclaw/clawscan/cmd/clawscan@latest`
- Source build: `make release VERSION=<version>`

## Before Tagging

1. Confirm the release branch is the intended source branch.
2. Confirm the repository and release assets are visible to the intended
   installers. Public Homebrew installs cannot fetch private GitHub release
   archives.
3. Run the local gate:

   ```bash
   go test ./...
   go vet ./...
   make release VERSION=v0.0.0-test
   ```

4. Inspect `dist/` and `dist/checksums.txt`.
5. Confirm the release workflow has access to one of these secrets:
   `HOMEBREW_TAP_TOKEN` or `HOMEBREW_TAP_GITHUB_TOKEN`.

The Homebrew token must be able to dispatch workflows and push to
`openclaw/homebrew-tap`. Missing tap credentials should not block GitHub release
artifacts, but they will skip the Homebrew formula update.

## Publish

Create and push a semver tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow will:

1. Build release archives with `make release VERSION=<tag>`.
2. Upload the archives and `checksums.txt` as workflow artifacts.
3. Publish a GitHub Release for the tag.
4. Dispatch `openclaw/homebrew-tap` to create or update
   `Formula/clawscan.rb` from the release archives.

Manual release publishing is also available from the workflow dispatch form.
Set `tag` to an existing `v*` tag and `publish` to `true`.

## Verify

After the workflow finishes:

1. Confirm the GitHub Release contains:
   - `clawscan_<tag>_darwin_amd64.tar.gz`
   - `clawscan_<tag>_darwin_arm64.tar.gz`
   - `clawscan_<tag>_linux_amd64.tar.gz`
   - `clawscan_<tag>_linux_arm64.tar.gz`
   - `clawscan_<tag>_windows_amd64.zip`
   - `checksums.txt`
2. Confirm `openclaw/homebrew-tap` contains `Formula/clawscan.rb` for the same
   version.
3. Test a fresh Homebrew install:

   ```bash
   brew update
   brew install openclaw/tap/clawscan
   clawscan --version
   ```

4. Test one raw archive install by downloading the matching archive, unpacking
   it, and running:

   ```bash
   ./clawscan --version
   ```

5. Confirm the version printed by both install paths matches the release tag.

## Rollback

If release artifacts are wrong, delete the broken GitHub Release and retag only
after understanding the mismatch. If only the Homebrew formula update is wrong,
fix the formula in `openclaw/homebrew-tap` or rerun its `update-formula.yml`
workflow with the correct inputs.
