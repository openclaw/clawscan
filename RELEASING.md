# Releases

`.github/workflows/release.yml` owns all shipped channels: GitHub archives for
Darwin, Linux and Windows, the `@openclaw/clawscan` npm package, and the OpenClaw
Homebrew tap. Prepare a dated changelog section on protected main and wait for
green push CI on the exact commit. With explicit release authorization, push an
annotated SSH-signed `vX.Y.Z` tag allowed by `.github/release-allowed-signers`.
The workflow builds once, signs and notarizes Darwin binaries, packs those same
binaries in npm, smokes the installed package, publishes through npm OIDC, and
creates a GitHub Release with changelog notes and checksums before the tap handoff.

Dispatch from main with `dry_run=true` (default) to run the same build, signing,
packing and smoke without publishing or creating tags. The separate npm artifact
promotion workflow is retired. Existing npm versions and GitHub Releases fail
closed; no overwrite or fallback publication is supported.

Secrets: `MACOS_SIGNING_P12`, `MACOS_SIGNING_P12_PASSWORD`, `ASC_KEY_ID`,
`ASC_ISSUER_ID`, `ASC_PRIVATE_KEY_P8`, and `HOMEBREW_TAP_TOKEN`. npm trusted
publishing names `openclaw/clawscan` and `release.yml`; no npm token is used.
Local `make release` and package smoke helpers remain build/verification only.
