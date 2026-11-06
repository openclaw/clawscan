# Changelog

## Unreleased

- **Breaking:** the `clawhub` and `clawhub-aig` profiles judge skills and plugins with an evidence-only Codex run (`gpt-6.1-sol`) that sees scanner results only. The new profile setting `judge.evidenceOnly` / `overview.evidenceOnly` removes the artifact copy from the command's workspace and refuses `{{ target.files }}`; the profile disables Codex's file, shell, image, web-search and code-execution tools (verified against codex-cli 0.164.0; its sub-agent tools stay offered but inherit the same restrictions). New prompt placeholders `{{ scanner_results }}` and `{{ run_context }}`. `judge.result` keeps the typed fields but no longer carries the Decisions `decision` record. The Decisions API judge remains available through `--judge`.
- Give scanner commands run against OpenClaw plugin targets a 30-minute budget (was 20 minutes); skill, file and URL targets keep 20 minutes. The judge and overview budgets are unchanged.
- Refresh Node setup to 7.1.0, use Node 24.22.2 for CI and docs, and Node 26.13.0 for release packaging.

- **Breaking for plugin targets:** add the plugin-only `aig-mcp` scanner (Tencent A.I.G `aig-mcp-scan` 0.2.0, patched in the runtime image to allow only confined read-only tools, refuse model-chosen MCP destinations and fail unusable reports) and the profile field `pluginScanners`. The `clawhub` profile now runs only `aig-mcp` for OpenClaw plugins, over a bounded copy without `node_modules`; skills keep `skillspector` and `aig`. Consumers that read `scanners.skillspector` or `scanners.aig` for plugin runs must read `scanners["aig-mcp"]` instead. Host runs need `AIG_MCP_SCAN_ALLOW_HOST_EXEC=1` ([#149](https://github.com/openclaw/clawscan/pull/149)).
- **Breaking:** the `clawhub` and `clawhub-aig` profiles take their verdict from the OpenAI Decisions API (`gpt-6-luna`) through the new `clawscan-decisions-judge` command in the runtime image, and add a Codex `gpt-6-luna` low-effort overview step for readable prose. `judge.result` now holds typed fields only: `verdict`, `confidence`, `dimensions.<name>.status`/`.confidence`, `scan_findings_in_context[]` (`ruleId`, `scanner`, `expected_for_purpose`, `probability`), and a new `decision` object with the model, usage, latency, verdict probabilities, and risk-signal probabilities. `summary`, dimension `detail`, finding `note`, and `user_guidance` move to the new top-level `overview.result`. Refusals, HTTP errors, and oversized input fail the judge with the real error.
- Add an optional, pluggable profile `overview.command` (`--overview <cmd>`, `--no-overview`). It runs after a completed verdict with the judge workspace plus `judge.json` and the `{{ judge.result }}` prompt placeholder, records `overview` in the run artifact, and never changes the verdict, gate, status, completeness, or exit status. Benchmark runs skip the profile overview.
- Run full CodeQL scans daily instead of on every main push, preserve PR and manual analysis, and start scans when draft PRs become ready for review.
- Summarize per-file SkillSpector accounting lists in the ClawHub judge prompt as counts plus a bounded sample. The full report stays in the judge workspace.
- **Breaking:** make the runner judge-agnostic. Remove the artifact-inspection receipt (challenge file, receipt validation, the `{{ artifact_inspection.required_file }}` placeholder, the `artifact_inspection` field in the bundled clawhub prompt and output schema, and the `challenge`, `requiredFile`, and `requiredFileSha256` fields on `judge.attempts`), the runner-level judge prompt budget (`judge prompt too large`), and every profile-name special case. A judge with an input limit enforces it itself; a failed judge command keeps its own error and is never retried. A judge command that exits successfully without a JSON object, including one that never writes `{{ output }}`, is retried once. `judge.attempts` is now recorded for every judge command run, not only for ClawHub profiles.
- **Breaking:** every profile uses one judge workspace layout (`artifact/`, `scanners/<id>.json`, and `metadata.json` with the run `context`), and SkillSpector scans the target itself for every profile (the ClawHub-only `artifact/` scan copy is gone). Usable partial SkillSpector evidence reaches any configured judge; without a judge it still fails the scanner. With a judge, SkillSpector reports must be nonempty JSON objects.
- **Breaking:** remove the `virustotal` and `clawscan-static` scanners. The `clawhub` profile now runs `skillspector` and `aig` (for skills; see `aig-mcp` above for plugins), and `openclaw-install-policy` runs `skillspector`. The install policy validates npm metadata preflights without scanning and returns a visible `warn` on native Windows instead of a static-only scan. Consumers that read `scanners["clawscan-static"]` must switch to another eligibility signal.

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
