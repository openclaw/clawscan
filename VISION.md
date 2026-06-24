## ClawScan Vision

ClawScan lets the community see, test, and improve how ClawHub detects malicious
skills.

ClawScan is an open, benchmarkable security scanning harness for agent skills.
It runs scanners, preserves their raw evidence, and optionally hands that
evidence to an external judge harness so the full scan process can be inspected,
tested, and improved.

This document explains the current state and direction of the project.
We are still early, so iteration is fast.
Project overview and developer docs: [`README.md`](README.md)

ClawScan started as the extraction of ClawHub's internal skill security scan
path into a standalone open source tool.

The goal is to make ClawHub's skill security process transparent and
improvable. Security researchers, contributors, and maintainers should be able
to see exactly how ClawHub scans skills today, try better scanner and judge
combinations, and submit changes that catch real malicious skills without
creating broad false positives.
That gives the community a practical hill-climbing loop for making skill
security scanning more robust over time.

The current focus is:

Priority:

- Show exactly how ClawHub performs skill security scans, including scanners,
  raw evidence, prompts, schemas, judge harnesses, and model settings
- Make it easy to test different combinations of scanners, harnesses, models,
  prompts, and schemas against the same targets
- Give security researchers a clear path to report missed malicious skills and
  submit fixes that prove those skills are caught without regressing known-good
  cases
- Run multiple scanners against one target and preserve their raw JSON evidence
- Keep secrets out of CLI flags, shell history, process lists, and artifacts
- Keep the CLI small enough that scanner comparison is easy to understand

Next priorities:

- Fill in real adapters for accepted scanner IDs that are currently stubs
- Improve fixture and corpus workflows for scanner comparison, missed-malicious
  reports, and false-positive regression checks
- Add lightweight eval workflows once one-off scan behavior is solid
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
too early into one canonical verdict. That visibility is what lets contributors
compare scanners honestly and understand why a judge prompt did or did not reach
a useful conclusion.

Built-in scanner support should focus on boring integration work:

- run the scanner
- validate required environment variables up front
- capture command status, stderr-derived errors, and raw JSON output
- support fixture-backed scanner results for comparison and regression checks

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

## ClawHub Transparency

ClawHub transparency is a required invariant for this extraction.
The standalone CLI must make it possible to see the same scan inputs ClawHub is
using in production: scanner evidence, prompt text, schema, judge harness, model,
and relevant runtime settings.

When exact parity matters, it should be provable with stable scanner fixtures
and byte-level hashes. That proof is not the product's purpose by itself; it is
the trust mechanism that lets the community know they are improving the same
process ClawHub actually runs.

ClawHub-specific verification helpers can live under `cmd/verify-clawhub-prompt`
or similar internal proof commands.
The public `clawscan` command should stay useful for anyone scanning skills,
whether or not they use ClawHub.

This matters most when someone finds a malicious skill that ClawHub missed.
They should be able to create a failing fixture, improve a scanner, prompt, or
judge harness, and show that the new setup catches the malicious skill without
turning benign skills into false positives.

## Setup

ClawScan is CLI-first by design.
For v1, command flags remain the override surface and the easiest path for
one-off runs. Named profiles add a small repeatability layer for common scanner
and judge combinations without making YAML mandatory.

Project `.clawscan.yml` files may define profiles and env var names, but secrets
must still come from environment variables. Plugin APIs, dashboards, and heavier
configuration systems can come later if repeated use proves they are worth the
extra surface area. Until then, the tool should prefer simple commands that are
easy to paste into CI, docs, and issue comments.

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
