## ClawScan Vision

ClawScan is the small, reproducible security runner for agent skills.
It runs scanners, preserves their raw evidence, and optionally hands that
evidence to an external judge harness.

This document explains the current state and direction of the project.
We are still early, so iteration is fast.
Project overview and developer docs: [`README.md`](README.md)

ClawScan started as the extraction of ClawHub's internal skill security scan
path into a standalone open source tool.

The goal: make skill security scanning boring, comparable, and reproducible
while keeping the public tool general-purpose.

The current focus is:

Priority:

- Reproduce ClawHub's current ClawScan setup char-for-char where needed
- Run multiple scanners against one target and preserve their raw JSON evidence
- Keep secrets out of CLI flags, shell history, process lists, and artifacts
- Keep the CLI small enough that scanner comparison is easy to understand

Next priorities:

- Fill in real adapters for accepted scanner IDs that are currently stubs
- Improve scanner fixture workflows for repeatable comparisons
- Add corpus/eval workflows once one-off scan behavior is solid
- Make artifact comparison easier without inventing a heavy benchmark platform

Contribution rules:

- One PR = one issue/topic. Do not bundle unrelated scanners, harness changes,
  and artifact schema changes together.
- Public CLI flags must stay general-purpose. ClawHub-specific proof helpers can
  live in internal commands, but the main `clawscan` command should not expose
  ClawHub-only concepts.
- Artifact changes should be treated as compatibility-sensitive even before a
  public release.

## Security

Security in ClawScan is evidence-first.
Scanners produce evidence; they do not become the policy engine by themselves.
The judge, when used, is an explicit external harness chosen by the operator.

Secrets must come from environment variables or from the external harness's own
configuration, not from ClawScan-specific secret flags.
Run artifacts record whether required env vars were present, never the secret
values.

Judge commands are powerful by design, so ClawScan keeps the boundary explicit:
it prepares a temporary workspace, shell-quotes generated placeholder paths, and
does not persist the rendered judge command into the artifact.

## Scanner Evidence

ClawScan should preserve scanner output as raw evidence for as long as possible.
Different scanners have different threat models, output schemas, confidence
signals, and false-positive profiles.

The artifact should make those differences visible instead of flattening them
too early into one canonical verdict.

Built-in scanner support should focus on boring integration work:

- run the scanner
- validate required environment variables up front
- capture command status, stderr-derived errors, and raw JSON output
- support fixture-backed scanner results for reproducible checks

## Judge Harness

The judge is optional.
Users should be able to run ClawScan as a scanner comparison tool without asking
a model or agent to adjudicate anything.

When a judge is used, ClawScan exposes a harness command through `--judge`.
The command can reference ClawScan-prepared values with placeholders such as
`{{ workspace }}`, `{{ prompt }}`, `{{ output_schema }}`, and `{{ output }}`.

This keeps ClawScan out of the model-provider framework business.
Codex, another agent harness, the OpenAI Responses API, the Vercel AI SDK, a
local script, or a future evaluator can all sit behind `--judge` without forcing
ClawScan to own those integrations directly.

The judge result must be a JSON object.
If a schema is relevant, the harness should enforce it and write the validated
object to `{{ output }}`.

## ClawHub Parity

ClawHub parity is a required invariant for this extraction.
The standalone CLI must be able to prove that the prompt handed to a judge
harness matches the prompt ClawHub would have produced for the same scanner
evidence.

That parity should be proven with stable scanner fixtures and byte-level hashes.
It should not require public ClawHub-specific flags on the main CLI.

ClawHub-specific verification helpers can live under `cmd/verify-clawhub-prompt`
or similar internal proof commands.
The public `clawscan` command should stay useful for anyone scanning skills,
whether or not they use ClawHub.

## Setup

ClawScan is CLI-first by design.
For v1, command flags are the configuration surface.

YAML configs, plugin APIs, dashboards, and persistent run profiles can come
later if repeated use proves they are worth the extra surface area.
Until then, the tool should prefer simple commands that are easy to paste into
CI, docs, and issue comments.

## Why Go?

ClawScan is a security-oriented CLI that shells out to other scanners and needs
portable, predictable artifact generation.
Go keeps the first version easy to install, easy to test, and easy to ship as a
single binary.

The judge harness remains external, so ClawScan does not need to become a
TypeScript or JavaScript runtime just to support model execution.

## What We Will Not Add (For Now)

- ClawHub-only flags on the public `clawscan` command
- A built-in policy engine that hides scanner evidence behind one verdict
- A built-in model-provider abstraction when `--judge` can call an external
  harness
- Secret-bearing CLI flags
- YAML config as a required v1 path
- A plugin architecture before scanner adapters prove the boundary
- A full eval/benchmark platform before one-off scan artifacts are stable
- Silent artifact schema churn once the format is published

This list is a roadmap guardrail, not a law of physics.
Strong user demand and strong technical rationale can change it.
