# ClawScan Docs

ClawScan is an open, benchmarkable security scanning harness for agent skills.

It gives security researchers, maintainers, and contributors one CLI for running
scanners, comparing raw evidence, and optionally passing that evidence into an
external judge harness. The point is not to hide scanner differences behind one
verdict. The point is to make those differences easy to see, test, and improve.

OpenClaw uses ClawScan to make ClawHub's production skill scanning visible and
improvable. The tool itself is general purpose and can be used by any project
that wants repeatable agent-skill security checks.

## Manual

| Page | Use it for |
| --- | --- |
| [Quickstart](quickstart.md) | Install, first scan, env vars, and common commands. |
| [Scanners](scanners.md) | Supported scanner IDs, upstream links, target support, and credentials. |
| [Judge harness](judge.md) | `--judge`, placeholders, prompt interpolation, and schema handoff. |
| [Benchmarks](benchmarks.md) | Running the supported OpenClaw security-signals dataset. |
| [Artifacts](artifacts.md) | `clawscan-run-v1` and `clawscan-benchmark-v1` JSON shapes. |
| [Development](development.md) | Tests, docs site build, releases, and ClawHub parity tooling. |

## Mental Model

ClawScan has three layers:

1. **Target**: a local skill file, a local skill directory, a scanner-supported
   URL, or a benchmark row materialized as a temporary skill directory.
2. **Scanners**: built-in adapters that produce raw JSON evidence.
3. **Judge**: an optional external command that interprets the evidence.

If no judge is configured, ClawScan is still useful as a scanner comparison
tool. If a judge is configured, ClawScan prepares the scanner evidence and paths
that the external harness needs.
