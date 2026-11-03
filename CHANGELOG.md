# Changelog

## Unreleased

- Run full CodeQL scans daily instead of on every main push, preserve PR and manual analysis, and start scans when draft PRs become ready for review.

## 0.3.1 - 2026-11-02

- Refresh the frozen SkillSpector certificate bundle to certifi 2026.10.23, preserving the Responses adapter patch. Runtime Python delivery remains a separate requirement for incident-key rejection. Thanks @joshavant. (#94)
- Let ClawHub judges investigate usable partial SkillSpector reports with `status: partial` and `reportPolicy: judge-gaps`, retaining raw findings, gaps, provenance, and artifact-backed inspection receipts. Missing, malformed, crashed, or unsuccessful reports still fail; other profiles keep existing scanner semantics. Consumers must explicitly support the partial status and policy pair ([#129](https://github.com/openclaw/clawscan/pull/129)).
- Preserve structured permission declarations and honor explicit manifest selection in multi-harness bundles while scanning the complete artifact root ([#96](https://github.com/openclaw/clawscan/pull/96), [#97](https://github.com/openclaw/clawscan/pull/97)).
- Reconcile scanner accounting for hidden files, ZIP members, and supported passive images without treating every analyzer as inspecting the same files ([#95](https://github.com/openclaw/clawscan/pull/95), [#101](https://github.com/openclaw/clawscan/pull/101)).
- Inspect larger vulnerability-advisory sets with bounded full queries and separate retained-evidence budgets; omitted evidence and failed enrichment remain incomplete ([#98](https://github.com/openclaw/clawscan/pull/98), [#100](https://github.com/openclaw/clawscan/pull/100), [#103](https://github.com/openclaw/clawscan/pull/103), [#107](https://github.com/openclaw/clawscan/pull/107)).
- Repair delimiter handling in Markdown prose, containers, tables, frontmatter, inline JSON, and CSV fields while preserving conservative shell-fence boundaries and raw security findings ([#99](https://github.com/openclaw/clawscan/pull/99), [#102](https://github.com/openclaw/clawscan/pull/102), [#105](https://github.com/openclaw/clawscan/pull/105), [#111](https://github.com/openclaw/clawscan/pull/111), [#112](https://github.com/openclaw/clawscan/pull/112), [#115](https://github.com/openclaw/clawscan/pull/115), [#124](https://github.com/openclaw/clawscan/pull/124), [#126](https://github.com/openclaw/clawscan/pull/126)).
- Use bounded Bash parsing for proven source roles and preserve quote boundaries, including nested and reconstructed operands. Check complete Bash fence bodies independently of surrounding Markdown prose, retaining partial reporting when traps or uncertain shell syntax affect interpretation ([#116](https://github.com/openclaw/clawscan/pull/116), [#130](https://github.com/openclaw/clawscan/pull/130), [#133](https://github.com/openclaw/clawscan/pull/133)).
- Recognize proven JavaScript data and validator values, native JSON formatting arguments, scalar console diagnostics and parenthesized native calls while retaining uncertainty for unsupported effects and executable uses ([#122](https://github.com/openclaw/clawscan/pull/122), [#123](https://github.com/openclaw/clawscan/pull/123), [#127](https://github.com/openclaw/clawscan/pull/127), [#128](https://github.com/openclaw/clawscan/pull/128), [#131](https://github.com/openclaw/clawscan/pull/131)).
- Inspect a bounded passive PDF subset on Linux, including decoded text, and validate canonical PCM WAVE evidence before accepting an explicit binary exclusion. Unsupported formats and layouts remain incomplete ([#104](https://github.com/openclaw/clawscan/pull/104), [#106](https://github.com/openclaw/clawscan/pull/106), [#125](https://github.com/openclaw/clawscan/pull/125)).
- Batch and pack source reviews, retain bounded scanner projections and completion records, and defer unused native parsing work while preserving source identities, findings, and deadline limits ([#108](https://github.com/openclaw/clawscan/pull/108), [#109](https://github.com/openclaw/clawscan/pull/109), [#117](https://github.com/openclaw/clawscan/pull/117), [#118](https://github.com/openclaw/clawscan/pull/118)).
- Refresh bundled Codex and Claude Code trust inputs and pin runtime base images across verification and publication ([#89](https://github.com/openclaw/clawscan/pull/89), [#121](https://github.com/openclaw/clawscan/pull/121)).

- Defer unused SkillSpector workflow imports so source-analysis helpers retain their existing time budgets. Verify the repaired runtime against the locked production SDKs as well as both native image platforms ([#132](https://github.com/openclaw/clawscan/pull/132), [#134](https://github.com/openclaw/clawscan/pull/134)).
- Bound complete SkillSpector model requests, including prompts, numbered source, relevant findings and response schemas. Split packets within the existing budget; retain inputs and fail before a provider call when a request cannot fit. Token counting does not download a vocabulary ([#136](https://github.com/openclaw/clawscan/pull/136)).

Scanner parser and dependency fixes require adoption of the corresponding runtime image. Binary release and worker adoption remain separate; these changes do not establish complete scanner coverage or recovery of every package.

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
