# Security Policy

If you believe you have found a security issue in ClawScan, report it privately
first.

Use GitHub's private vulnerability reporting flow for this repository. Do not
open a public issue or pull request that discloses an unpatched vulnerability,
exploit path, credential, or security-sensitive proof of concept. If you are not
sure where the issue belongs, email security@openclaw.ai and we will route it.

## Supported Versions

Security fixes are applied to the latest released version and the latest `main`
branch.

| Version | Supported |
| --- | --- |
| latest release | yes |
| `main` | yes |
| older releases | no |

## What To Include

Good reports include:

- affected ClawScan version, commit SHA, and install method
- operating system and architecture
- scanner IDs, profile/config, benchmark, or `--judge` command involved
- required environment variable names, without secret values
- clear reproduction steps or a minimal proof of concept
- expected impact and attack scenario
- relevant logs or artifacts with secrets redacted

## Trust Model

ClawScan is a local CLI security scanning harness. It runs configured scanner
adapters against local files, URLs, or benchmark material, and it may run an
optional external judge command supplied by the operator.

Current safety boundaries:

- ClawScan validates scanner and judge environment requirements up front when
  it knows them.
- ClawScan records only secret-safe environment presence in artifacts.
- ClawScan redacts known secret environment values from scanner and judge
  errors/results before writing artifacts.
- Fixture-backed scanner results can be used when live scanners or credentials
  should not run.

Current non-goals:

- ClawScan does not sandbox scanners or judge commands by default.
- ClawScan does not make untrusted scanners, judge harnesses, shells, package
  managers, or local workspaces safe to execute.
- ClawScan does not validate that third-party scanner output is complete or
  correct.
- ClawScan does not make a malicious skill safe to install or run.

Treat every scanner command and `--judge` command as local code execution. Run
only tools and profiles you trust, and review artifacts before sharing them.

## Reporting Malicious Skills

If your report is about a malicious or deceptive skill listing rather than a
bug in ClawScan itself, report it through the relevant marketplace or upstream
publisher. For ClawHub listings, use ClawHub's listing report flow so moderators
can triage the live content.

If a ClawScan bug lets malicious content evade a configured scan, causes false
results, leaks secrets, corrupts artifacts, or breaks benchmark/submission
validation, report it here privately.
