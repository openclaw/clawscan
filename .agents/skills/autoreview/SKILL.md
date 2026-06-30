---
name: autoreview
description: "Pre-commit/ship bundle-only code review: Codex default; optional Claude, Pi, or Droid."
---

# Auto Review

Run the bundled structured review helper as a closeout check. This is code review, not Guardian `auto_review` approval routing.

Codex review is the default when no engine is set. It uses `gpt-5.5` by default, usually delivers the best review results, and should remain the normal final closeout engine. Claude review is optional and uses `claude-fable-5` by default.

Use when:

- user asks for Codex review / Claude review / Pi review / Droid review / autoreview / second-model review
- after non-trivial code edits, before final/commit/ship
- reviewing a local branch or PR branch after fixes

## Contract

- Treat review output as advisory. Never blindly apply it.
- Verify every finding by reading the real code path and adjacent files.
- Read dependency docs/source/types when the finding depends on external behavior.
- Reject unrealistic edge cases, speculative risks, broad rewrites, and fixes that over-complicate the codebase.
- Prefer small fixes at the right ownership boundary; no refactor unless it clearly improves the bug class.
- When an accepted finding shows a bug class or repeated pattern, inspect the current PR scope for sibling instances before fixing.
- Fix the scoped bug class at once when practical; stop at touched surfaces, owner boundaries, and clear follow-up territory.
- Keep going until structured review returns no accepted/actionable findings only while the work remains inside the original task scope.
- If a review-triggered fix changes code, rerun focused tests and rerun the structured review helper.
- For security-audit suppression changes, verify accepted findings remain auditable: suppressed findings stay in structured output, active output keeps an unsuppressible suppression notice, and aggregate findings cannot hide unrelated active risk.
- Never switch or override the requested review engine/model. If the review hits model capacity, retry the same command a few times with the same engine/model.
- Be patient with large bundles. Structured review can take up to 30 minutes while the model call is active.
- Treat heartbeat lines like `review still running: ... elapsed=... pid=...` as healthy progress, not a hang. Let the helper continue while heartbeats are advancing. Pass `--stream-engine-output` when live engine text is useful; Codex and Claude filter tool/file chatter, other engines pass raw output through.
- Do not kill a review just because it has been quiet for 2-5 minutes, or because it is still running under the 30-minute window. Inspect the process only after missing multiple expected heartbeats, after 30 minutes, or after an obviously failed subprocess; prefer letting the same helper command finish.
- Reviewers receive the complete bounded bundle only. Filesystem, shell, plugin, MCP, browser, and web-search tools stay disabled because read-only access is not a repository-scoped read jail.
- Security perspective is always included, but it should not cripple legitimate functionality. Report security findings only when the change creates a concrete, actionable risk or removes an important safety check.
- For regression provenance, keep roles separate: blamed code author, blamed PR author, PR merger/committer, current PR author, and PR/date. If no blamed PR is traceable, use the blamed commit as the provenance: commit SHA, date, and author username. Do not guess a merger or frame missing PR metadata as a separate finding.
- If the blamed PR was merged by `clawsweeper[bot]` or another automation, identify the human trigger when practical. Check timeline/comments first; if rate-limited, use gitcrawl/cache or public PR HTML. Look for maintainer commands such as `@clawsweeper automerge`, `/landpr`, or labels/status comments that armed automerge. Report `automerge triggered by @login`; if not found, say trigger unknown.
- Do not invoke built-in `codex review`, nested reviewers, or reviewer panels from inside the review. The helper builds one bundle, calls one selected engine, validates one structured result, and stops.
- Stop as soon as the helper exits 0 with no accepted/actionable findings. Do not run an extra review just to get a nicer "clean" line, a second opinion, or clearer closeout wording.
- Treat the helper's successful exit plus absence of actionable findings as the clean review result, even if the underlying Codex CLI output is terse.
- Multi-reviewer panels are opt-in only. Use them when explicitly requested or when risk justifies the extra spend; the main agent still verifies every accepted finding before fixing.
- If rejecting a finding as intentional/not worth fixing, add a brief inline code comment only when it explains a real invariant or ownership decision that future reviewers should know.
- If `gh`/Gitcrawl reports `database disk image is malformed`, run `gitcrawl doctor --json` once to let the portable cache repair before retrying review; do not bypass the shim unless repair fails and freshness requires live GitHub.
- If Gitcrawl reports a portable manifest mismatch, source/runtime DB health error, or stale portable-store checkout, run `gitcrawl doctor --json` and inspect `source_db_health`, `runtime_db_health`, and `portable_store_status` before falling back to live GitHub.
- Do not push just to review. Push only when the user requested push/ship/PR update.

## Scope Governor

Autoreview is a closeout gate, not permission to rewrite the task.

Before the first review, freeze a scope baseline: original request or issue, target branch, intended behavior, owner boundary, changed files, and non-test LOC. For inherited or already-bloated branches, use the intended PR diff as the baseline rather than accepting all existing branch drift.

Before patching a finding, classify it:

- **In-scope blocker**: the finding is introduced by the current diff, affects the same owner boundary, and can be fixed without changing the task's contract.
- **Follow-up**: the finding is real but belongs to an adjacent bug class, sibling surface, cleanup, or broader hardening track.
- **Stop-and-escalate**: the finding requires a new protocol/config/storage/public API contract, a different owner boundary, a release-process change, or a design choice outside the original request.

Stop patching and report the scope break instead of continuing when:

- a narrow PR turns into an architecture change, protocol change, migration, or release-process change;
- the diff grows past 2x the original files or non-test LOC without explicit approval to expand scope;
- two review-triggered patch cycles have not converged; pause and reclassify every remaining finding before another edit;
- the best fix is "define the canonical contract first" rather than another local inference layer;
- fixing the accepted finding would make the PR no longer describe the same behavior, issue, or owner boundary.

After the two-cycle pause, continue only when every remaining accepted finding is still an in-scope blocker. Otherwise preserve the useful analysis, identify the smallest safe landed subset if one exists, and open or request a follow-up for the larger fix. Do not keep committing speculative fixes just to satisfy the reviewer.

Do not stack or push review-triggered fix commits while scope classification or focused proof is unresolved. Keep exploratory edits local until the cycle is proven in scope; if scope breaks, remove them from the landing lane instead of preserving them as branch history.

Critical exceptions must be explicit: active data loss, crash, broken install/upgrade, release blocker, or concrete security exposure. If the exception is not one of those, it is not critical enough to blow up scope.

## Release Branches And Release Process

On release, beta, stable, hotfix, signing, notarization, appcast, package-publish, or release-check work, use freeze discipline even when the branch name is not release-like:

- Fix only release blockers, failed release infrastructure, exact backports, install/upgrade breakage, data loss, crashes, or concrete security exposure.
- Treat non-blocking autoreview findings as follow-ups for `main`, not reasons to broaden the release branch.
- Do not introduce new product behavior, config surface, protocol shape, migration, plugin ownership, docs narrative, or process policy unless it directly unblocks the release.
- Keep proof tied to the release target: exact branch/ref, failing check or shipped-risk reason, smallest command/proof, and whether the fix must also forward-port to `main`.
- If review discovers a real but non-critical design problem during release closeout, stop with a follow-up issue/PR plan; do not use the release branch as the refactor lane.

## Skill Path (set once)

Set the skill script paths once, then use `"$AUTOREVIEW"` and `"$AUTOREVIEW_HARNESS"` in the examples below.

Choose one:

```bash
# Project-local skill in the current repo:
export AUTOREVIEW=".agents/skills/autoreview/scripts/autoreview"
export AUTOREVIEW_HARNESS=".agents/skills/autoreview/scripts/test-review-harness"
```

```bash
# Source checkout of openclaw/agent-skills:
export AUTOREVIEW="skills/autoreview/scripts/autoreview"
export AUTOREVIEW_HARNESS="skills/autoreview/scripts/test-review-harness"
```

```bash
# Global skill:
export AGENTS_HOME="${AGENTS_HOME:-$HOME/.agents}"
export AUTOREVIEW="$AGENTS_HOME/skills/autoreview/scripts/autoreview"
export AUTOREVIEW_HARNESS="$AGENTS_HOME/skills/autoreview/scripts/test-review-harness"
```

When using Claude Code, set `AGENTS_HOME="$HOME/.claude"` for global skills. Project-local skills live under `.claude/skills/` in the current repo.

## Pick Target

Dirty local work:

```bash
"$AUTOREVIEW" --mode local
```

Use this only when the patch is actually unstaged/staged/untracked in the
current checkout. `--mode uncommitted` is accepted as an alias for `--mode local`.
For committed, pushed, or PR work, point the helper at the commit
or branch diff instead; do not force dirty modes just
because the helper docs mention dirty work first. A clean local review
only proves there is no local patch.

Branch/PR work:

```bash
"$AUTOREVIEW" --mode branch --base origin/main
```

Optional review context is first-class. Prompt files and datasets must be repo-relative so review bundles cannot pull arbitrary host files:

```bash
"$AUTOREVIEW" --mode branch --base origin/main --prompt-file review-notes.md --dataset evidence.json
```

If an open PR exists, use its actual base:

```bash
base=$(gh pr view --json baseRefName --jq .baseRefName)
"$AUTOREVIEW" --mode branch --base "origin/$base"
```

Committed single change:

```bash
"$AUTOREVIEW" --mode commit --commit HEAD
```

Use commit review for already-landed or already-pushed work on `main`. Reviewing
clean `main` against `origin/main` is usually an empty diff after push. For a
small stack, review each commit explicitly or review the branch before merging
with `--base`.

## Parallel Closeout

Format first if formatting can change line locations. Then it is OK to run tests and review in parallel:

```bash
"$AUTOREVIEW" --parallel-tests "<focused test command>"
```

On Windows, the default `--parallel-tests` shell preserves the platform `cmd.exe`
semantics used by Python `shell=True`. Use `--parallel-tests-shell powershell`
or `--parallel-tests-shell pwsh` when the focused test command is PowerShell-specific.

Tradeoff: tests may force code changes that stale the review. If tests or review lead to code edits, rerun the affected tests and rerun review until no accepted/actionable findings remain. Once that rerun exits cleanly, stop; do not spend another long review cycle on redundant confirmation.

## Review Panels

Run multiple reviewers against one frozen bundle:

```bash
"$AUTOREVIEW" --reviewers codex,claude,pi,droid
```

`--panel` is shorthand for Codex plus Claude unless `--engine` changes the first reviewer:

```bash
"$AUTOREVIEW" --panel
```

Set reviewer models and thinking/effort explicitly:

```bash
"$AUTOREVIEW" --reviewers codex,claude --model codex=gpt-5.5 --thinking codex=high --model claude=claude-fable-5 --thinking claude=max
```

Inline syntax is also supported for simple model IDs:

```bash
"$AUTOREVIEW" --reviewers codex:gpt-5.5:high,claude:claude-fable-5:max
```

For models with slashes or extra colons, prefer keyed form:

```bash
"$AUTOREVIEW" --engine pi --model anthropic/claude-sonnet-4 --thinking high
"$AUTOREVIEW" --engine droid --model claude-opus-4-8 --thinking low
"$AUTOREVIEW" --reviewers codex,pi --model codex=gpt-5.5 --model pi=anthropic/claude-sonnet-4
"$AUTOREVIEW" --reviewers codex,droid --model codex=gpt-5.5 --model droid=claude-opus-4-8
```

## Models and thinking

The helper accepts `--model` globally or per engine (`engine=model`) and `--thinking` globally or per engine (`engine=level`). Repeat either flag for multiple reviewers.

Recommended model defaults:

| Engine              | Default model    | Source note                                           |
| ------------------- | ---------------- | ----------------------------------------------------- |
| **codex** (default) | `gpt-5.5`        | OpenAI's current GPT-5.5 alias                        |
| **claude**          | `claude-fable-5` | Anthropic's most capable widely released Claude model |

CLI flags and environment variables override these defaults. Droid and Pi do not get built-in model defaults here because their provider catalogs are external to the Codex/Claude closeout path and may vary by installation.

| Engine              | Model flag                 | Example model IDs                                                            | Thinking flag                 | Accepted levels                                     |
| ------------------- | -------------------------- | ---------------------------------------------------------------------------- | ----------------------------- | --------------------------------------------------- |
| **codex** (default) | `codex --model X exec ...` | `gpt-5.5`, `gpt-5.5-2026-04-23`                                              | `-c model_reasoning_effort=Y` | `none`, `minimal`, `low`, `medium`, `high`, `xhigh` |
| **claude**          | `claude --model X`         | `claude-fable-5`, `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5` | `--effort Y`                  | `low`, `medium`, `high`, `xhigh`, `max`             |
| **droid**           | `droid exec --model X`     | `claude-opus-4-8`, Factory model IDs                                         | `-r, --reasoning-effort Y`    | `off`, `none`, `low`, `medium`, `high`              |
| **pi**              | `pi --model X`             | `anthropic/claude-sonnet-4`, `openai/gpt-4o`                                 | `--thinking Y`                | `off`, `minimal`, `low`, `medium`, `high`, `xhigh`  |

Claude also supports `--fallback-model a,b` for availability-based fallback chains ([model-config](https://code.claude.com/docs/en/model-config)). Current Claude docs note that auth, billing, rate-limit, request-size, and transport errors do not trigger fallback, and the changelog documents interactive-session support in `v2.1.166`.

Examples matching current `main` behavior:

```bash
# Codex with explicit model and reasoning
"$AUTOREVIEW" --engine codex --model gpt-5.5 --thinking high

# Claude Code aliases or full model names, with optional availability fallback
"$AUTOREVIEW" --engine claude --model claude-fable-5 --thinking max
"$AUTOREVIEW" --engine claude --model claude-fable-5 --fallback-model claude-opus-4-8,claude-sonnet-4-6

# Factory Droid with explicit model and reasoning effort
"$AUTOREVIEW" --engine droid --model claude-opus-4-8 --thinking low

# Pi with explicit model and thinking level
"$AUTOREVIEW" --engine pi --model anthropic/claude-sonnet-4 --thinking high --pi-bin pi
```

### Environment defaults

CLI flags take precedence over environment variables.

| Variable                           | Purpose                                                                 |
| ---------------------------------- | ----------------------------------------------------------------------- |
| `AUTOREVIEW_MODEL`                 | Override the built-in default `--model` for all engines                 |
| `AUTOREVIEW_THINKING`              | Default `--thinking` for all engines                                    |
| `AUTOREVIEW_FALLBACK_MODEL`        | Default Claude `--fallback-model` chain                                 |
| `AUTOREVIEW_<ENGINE>_MODEL`        | Per-engine model override, for example `AUTOREVIEW_CODEX_MODEL=gpt-5.5` |
| `AUTOREVIEW_<ENGINE>_THINKING`     | Per-engine thinking override                                            |
| `AUTOREVIEW_CLAUDE_FALLBACK_MODEL` | Claude-only fallback chain                                              |

Codex maps thinking to `model_reasoning_effort`. Claude maps thinking to `--effort`. Droid maps thinking to `-r, --reasoning-effort`. Pi maps thinking to `--thinking`. Only Claude accepts `--fallback-model`; global CLI/env fallback requires at least one Claude reviewer, and engine-specific fallback overrides require that reviewer to be selected. Non-Claude fallback overrides, including `AUTOREVIEW_<NONCLAUDE>_FALLBACK_MODEL`, fail closed instead of being silently ignored.

## Review engine isolation

When autoreview runs inside the repository under review, external reviewer CLIs must not load project-local trust or configuration that the branch controls.

| Engine     | Isolation flags                                                                                                                                                                                                        | Reference                                                                  |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **codex**  | Neutral temporary cwd, auth-only config overrides, `--strict-config`, reviewed-repo config/rules disabled, read-only sandbox, and every local/web/plugin tool feature disabled                                         | Codex CLI `exec --help` and `features list`                                |
| **claude** | Neutral temporary cwd, `--safe-mode --setting-sources user --strict-mcp-config --disallowedTools mcp__* --tools ""` (`--safe-mode` requires Claude Code `v2.1.169+`)                                                   | Claude Code [CLI reference](https://code.claude.com/docs/en/cli-reference) |
| **droid**  | Neutral temporary cwd, complete bounded review bundle only, default read-only autonomy, and `--disabled-tools *`                                                                                                       | Droid CLI `exec --help`                                                    |
| **pi**     | Neutral temporary cwd, `--no-approve --no-session --no-context-files --no-extensions --no-skills --no-prompt-templates --no-themes --no-tools`; requires Pi `v0.79.0+` because older binaries can ignore unknown flags | Pi CLI `--help`                                                            |

Every reviewer subprocess receives a sanitized environment that removes credential-shaped variables and sensitive auth-file pointers before the untrusted review bundle is supplied. Environment-variable API key authentication is intentionally not forwarded; authenticate reviewer CLIs through their persisted login or platform keychain instead. Copilot and OpenCode currently fail closed because their review modes cannot disable all filesystem/web tools.

Codex `--ignore-user-config` skips config loading for the exec run. Autoreview reconstructs only the documented authentication/workspace settings from `CODEX_HOME/config.toml`, then uses `--strict-config` and disables shell, unified-exec, browser, app, plugin, MCP, hook, image, and multi-agent feature surfaces. Claude safe mode disables project hooks, skills, plugins, MCP servers, and CLAUDE.md; the explicit empty tool set removes filesystem and web access. Droid and Pi also run from neutral temporary directories with every tool disabled.

Any diff or evidence input larger than the configured bundle ceiling fails closed. Autoreview never emits a clean verdict over truncated review input.

## Context Efficiency

Run the helper directly so target selection, engine choice, structured validation, and exit status all stay in one path. If output is noisy, summarize the completed helper output after it returns; do not ask another agent or reviewer to rerun the review.

## Helper

After setting `AUTOREVIEW` and `AUTOREVIEW_HARNESS` above:

```bash
"$AUTOREVIEW" --help
```

The smoke harness has thin shell wrappers over a shared Python implementation:

```bash
"$AUTOREVIEW_HARNESS" --fixture benign --engine codex
```

On native Windows, invoke the extensionless Python helper through Python:

```powershell
python skills\autoreview\scripts\autoreview --help
```

and the smoke harness:

```powershell
skills\autoreview\scripts\test-review-harness.ps1 -Fixture benign -Engine codex
```

The helper:

- chooses dirty local changes first
- accepts `--mode uncommitted` as an alias for `--mode local`
- otherwise uses current PR base if `gh pr view` works
- otherwise uses `origin/main` for non-main branches
- does not fetch automatically during branch review; the selected base ref must already resolve locally
- supports bundle-only `codex`, `claude`, `droid`, and `pi` review; `copilot` and `opencode` fail closed until they can enforce a no-tools read jail; default is `AUTOREVIEW_ENGINE` or `codex`
- resolves bare `git`, `gh`, reviewer, and PowerShell shell commands from absolute `PATH` entries only, never from the reviewed checkout; explicit relative `--*-bin` paths are resolved from the reviewed repository root
- strips credential-shaped environment variables and sensitive auth-file pointers before launching reviewer subprocesses
- use `--mode commit --commit <ref>` for already-committed work, especially clean `main` after landing
- should be left in `--mode auto` or forced to `--mode branch` for PR/branch work; do not force `--mode local` after committing
- writes only to stdout unless `--output`, `--json-output`, or live streamed engine stderr is set
- supports `--dry-run`, `--parallel-tests`, `--parallel-tests-shell`, `--prompt`, repo-relative `--prompt-file`, repo-relative `--dataset`, and commit refs; `--no-tools` and `--no-web-search` remain compatibility flags because both are always enforced
- supports `--stream-engine-output` or `AUTOREVIEW_STREAM_ENGINE_OUTPUT=1` for live engine text while preserving structured validation; Codex and Claude hide tool/file event details, emit compact activity summaries, and report usage at turn completion
- supports opt-in review panels with `--panel` / `--reviewers`, plus per-engine `--model`, `--thinking`, and Claude `--fallback-model`
- uses built-in model defaults `codex=gpt-5.5` and `claude=claude-fable-5`; honors `AUTOREVIEW_MODEL`, `AUTOREVIEW_THINKING`, `AUTOREVIEW_FALLBACK_MODEL`, and per-engine `AUTOREVIEW_<ENGINE>_MODEL` / `AUTOREVIEW_<ENGINE>_THINKING` environment overrides when CLI flags are omitted
- disables all reviewer filesystem, shell, browser, web-search, plugin, MCP, and agent tools; reviewers reason only over the complete bounded bundle
- runs Codex from a neutral directory with auth-only settings, strict feature validation, reviewed-repo instructions/config/rules disabled, no tool features, a read-only sandbox, and structured output
- runs Claude from a neutral directory with `--safe-mode` (`v2.1.169+`), `--setting-sources user`, MCP disabled, an empty tool set, and `--fallback-model` when set
- runs Droid with `droid exec` from a neutral temporary directory with all tools disabled, forwards `--model` and `-r, --reasoning-effort`, and switches `--output-format` to `stream-json` when streaming is enabled
- runs Pi `v0.79.0+` from neutral temporary directories with `--no-approve`, `--no-session`, disabled Pi context/resource loading, and no tools
- rejects Copilot and OpenCode reviews until those CLIs expose enforceable no-tools review modes
- rejects oversized diffs/evidence instead of truncating them and potentially issuing an incomplete clean verdict
- prints `review still running: <engine> elapsed=<seconds>s pid=<pid>` to stderr at long-running intervals while waiting for the selected review engine, unless streamed output or compact Codex activity has been visible recently
- prints `autoreview clean: no accepted/actionable findings reported` when the selected review command exits 0
- exits nonzero when accepted/actionable findings are present

## Final Report

Include:

- review command used
- tests/proof run
- findings accepted/rejected, briefly why
- the clean review result from the final helper/review run, or why a remaining finding was consciously rejected

Do not run another review solely to improve the final report wording. If the final helper run exited 0 and produced no accepted/actionable findings, report that exact run as clean.
