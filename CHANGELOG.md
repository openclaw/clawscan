# Changelog

## Unreleased

## 0.3.0 - 2026-10-23

**Highlights:** Retain opt-in scan and judge lifecycle evidence, protect scan inputs during cancellation, and strengthen inspection receipts and runtime certificate trust.

- Add opt-in phase and bounded child-judge lifecycle diagnostics that survive outer scan interruption without exposing commands, paths, or raw output. Thanks @Patrick-Erichsen (#77, #79).
- Preserve cancellation and preparation evidence, reject unsafe output aliases, and protect scan inputs and loaded configuration from overwrite. Thanks @Patrick-Erichsen (#91).
- Bind versioned judge inspection receipts to required-file hashes and canonical inspected paths, and retry invalid inspection once within the original deadline. Consumers validating receipt keys must accept the version 2 schema. Thanks @Patrick-Erichsen (#76, #80, #82).
- Retry transient A.I.G stream overload within the original deadline and finish cleanup before returning caller interrupts. Thanks @Patrick-Erichsen (#81, #83).
- Parallelize SkillSpector discovery while rejecting incomplete evidence; preserve distinct finding identities, recognize fully inspected reference caveats, separate MCP applicability from batch admission, and resolve bundle plugins by canonical family identity. Thanks @Patrick-Erichsen (#84, #86, #87, #88, #90).
- Update the bundled Claude runtime to reject compromised certificate-authority keys and pin Node releases with incident-key rejection. Thanks @joshavant (#74, #75).
- Publish runtime images only from verified native platform builds (#85).
- Pin CI and release setup explicitly to Go 1.27.3 so setup-go cannot select the older language minimum.
- Add an opt-in live judge inspection check on Ubuntu 22.04 that verifies package-file receipts without publishing. Thanks @Patrick-Erichsen (#70).
- Update the text-processing dependency to golang.org/x/text v0.43.0 while retaining the Go 1.27.1 source minimum.

## 0.2.1 - 2026-10-20

**Highlights:** Patch certificate validation in release binaries and verify signed macOS packages on Xcode 27.

- Build with Go 1.27.3 to fix the reachable GO-2026-6809 crypto/x509 certificate-validation vulnerability while retaining the Go 1.27.1 source minimum.
- Move macOS CI and release verification to Xcode 27 with Rosetta for x86_64 and retain the existing macOS 13 minimum in both release and npm binaries.
- Keep mocked scanner/context tests independent of an installed Docker CLI while preserving sandbox enforcement checks.

- Refresh bundled Cisco, Snyk, Socket, Claude Code, and Codex tools while retaining the existing Node.js and Python runtime floors and two-day dependency cooldown.
- Preserve Docker sandbox paths containing commas or quotation marks without changing read-only or writable mount permissions. Thanks @SebTardif (#64).
- Use one shared autoreview installation from `openclaw/agent-skills`; repository entrypoints now receive upstream fixes without copied helpers or test suites.

- Use Codex with high reasoning for both bundled ClawHub judges and forward SkillSpector model/reasoning and optional A.I.G reasoning settings into scanner sandboxes.

## 0.2.0 - 2026-09-22

**Highlights:** Preserve scanner evidence, bound benchmark input memory, and identify worker-owned containers for cleanup.

- Preserve every scanner report when sanitized target, profile, or custom scanner names collide with each other or generated numeric suffixes (#54).
- Fix unbounded memory use when loading benchmark `--ids` from files or HTTP, including whitespace-padded IDs; document selection limits and preserve full-set JSONL support. Thanks @SebTardif (#47).
- Label worker-owned Docker containers with optional run and command IDs so supervisors can clean up after cancellation. Thanks @jesse-merhi (#55).
- Prevent large Hugging Face `Retry-After` values from overflowing into immediate retries while preserving server cooldowns and cancellation (#58).
- Add `--platform` to build smaller npm tarballs for one supported operating system and architecture while retaining the default universal package. Thanks @vincentkoc (#56).
- Repair contributor links and add the missing scanner-adapter guide. Thanks @atarico for the documentation report (#57).
- Refresh bundled scanner tools and Go dependencies; source builds now require Go 1.27.1, and the Docker runtime uses Node.js 24 LTS (#59).
- Publish changelog-backed release notes with verified npm metadata and show live CI and release status badges.
