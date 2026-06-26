---
name: report-clawhub-malicious-skill
description: >-
  Use when a researcher, maintainer, or contributor found or suspects a
  malicious skill on ClawHub and needs a private reporting workflow: opening a
  GitHub private vulnerability report, preparing a proposal-only PR, creating
  `proposals/<GHSA-ID>/clawscan.yml`, running ClawScan against the malicious
  skill and SkillTrustBench, and explaining what evidence belongs in private
  versus public channels.
---

# Report ClawHub Malicious Skill

## Overview

Use this workflow to help someone report a malicious ClawHub skill and propose
a ClawScan profile change that catches it. Keep sensitive details private and
make the public PR contain only the candidate ClawScan config.

## Safety Boundary

Separate private evidence from public contribution material:

- Put live malicious skill URLs/slugs, impact, exploit details, reproduction
  notes, and private ClawScan artifacts in GitHub private vulnerability
  reporting.
- Do not paste secrets, exploit payloads, private artifacts, or live bypass
  details into public issues, public PR text, README edits, or config comments.
- Do not ask the reporter to execute the suspicious skill. ClawScan should scan
  a local copy as data; it should not run the skill's behavior.
- If the reporter does not have a GHSA/private report id yet, have them open
  the private report first and wait for the identifier before opening the public
  proposal PR.

## Workflow

1. Open a GitHub private vulnerability report.

   Ask the reporter to include:

   - affected ClawHub skill URLs or slugs
   - why the current `clawhub` profile missed it
   - why the proposed ClawScan config catches it
   - local ClawScan artifact paths or attached artifacts
   - any private reproduction context maintainers need

2. Create a proposal-only branch and config.

   The public PR should add only:

   ```text
   proposals/<GHSA-ID>/clawscan.yml
   ```

   The file must define a `clawhub` profile. Start from the current profile and
   change only what is needed to catch the reported case:

   ```yaml
   version: 1
   profiles:
     clawhub:
       scanners:
         - skillspector
         - virustotal
         - clawscan-static
       judge:
         command: >
           # candidate judge command, if changed
   ```

   Do not edit the official bundled profile files in the proposal PR:

   - `internal/profiles/clawhub/clawscan.yml`
   - `internal/profiles/clawhub/prompt.md`
   - `internal/profiles/clawhub/output.schema.json`

3. Prove the candidate catches the reported skill locally.

   Use a local copy of the suspicious skill:

   ```bash
   clawscan /path/to/suspect-skill \
     --config proposals/<GHSA-ID>/clawscan.yml \
     --profile clawhub \
     --output ./artifacts/reported-skill-candidate.json
   ```

   If useful, compare against the built-in profile:

   ```bash
   clawscan /path/to/suspect-skill \
     --profile clawhub \
     --output ./artifacts/reported-skill-current.json
   ```

   The public PR should not include the private artifacts unless maintainers say
   the contents are safe to publish. Reference them in the private report.

4. Run a local benchmark smoke when practical.

   This does not replace maintainer validation, but it helps catch obvious
   regressions before opening the PR:

   ```bash
   clawscan benchmark SkillTrustBench \
     --config proposals/<GHSA-ID>/clawscan.yml \
     --profile clawhub \
     --limit 10 \
     --output ./artifacts/skilltrustbench-candidate-smoke.json
   ```

5. Open the public PR.

   Keep the PR text minimal:

   - state that a private vulnerability report exists
   - point to `proposals/<GHSA-ID>/clawscan.yml`
   - do not include sensitive skill details
   - say maintainers should run the official `SkillTrustBench Profile Gate`

6. Explain maintainer validation.

   Maintainers run the official gate against the proposal:

   ```bash
   clawscan benchmark SkillTrustBench \
     --config proposals/<GHSA-ID>/clawscan.yml \
     --profile clawhub \
     --output ./artifacts/skilltrustbench-candidate.json
   ```

   The proposal's `clawhub` profile shadows the built-in profile for that run.
   Maintainers review the private report, upload/preserve the benchmark
   artifact, update the README benchmark block, and port accepted behavior into
   the bundled `clawhub` profile in a follow-up change.

## Output Shape

When walking someone through the process, end with:

- private report checklist
- exact proposal file path
- candidate config draft or edits needed
- local ClawScan commands to run
- public PR checklist
- clear note that maintainers own the official SkillTrustBench gate and final
  built-in profile port
