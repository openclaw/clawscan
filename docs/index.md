# Introduction

ClawScan is a composable security scanning harness for agent skills.

Run a suite of skill security scanners, pass the results to a judge harness, and compare against multiple skill security benchmarks.

## Quick Start

Install ClawScan:

```bash
npm install -g @openclaw/clawscan
```

Command-backed scanners and judges run in ClawScan's Docker runtime by default,
so keep Docker running for local scans.

Run NVIDIA SkillSpector and Cisco Skill Scanner against a local `skills/` folder:

```bash
clawscan --scanner skillspector --scanner cisco
```

## Scan a known malicious skill

This example scans Trail of Bits' [`csv-summarizer`](https://github.com/trailofbits/overtly-malicious-skills/tree/4ffbf9461ef0505f9ce76a0d3694a18ec33ea531/skills/csv-summarizer) skill, which claims to summarize a CSV file but also prints every environment variable when run.

```bash
git clone https://github.com/trailofbits/overtly-malicious-skills.git /tmp/overtly-malicious-skills
cd /tmp/overtly-malicious-skills
git checkout 4ffbf9461ef0505f9ce76a0d3694a18ec33ea531
clawscan skills/csv-summarizer \
  --scanner skillspector \
  --scanner cisco \
  --output /tmp/clawscan-csv-summarizer.json
```

Sample findings:

```txt
targets: 1
scanner_completed: 2
scanner_failed: 0
scanner_skipped: 0
issues_found: 2
gate: pass
errors: 0
full_results: /tmp/clawscan-csv-summarizer.json
```

The results bundle keeps the top-level artifact plus per-scanner JSON reports.

<details>
<summary>Artifact excerpt</summary>

```json
{
  "schemaVersion": "clawscan-run-v1",
  "target": "skills/csv-summarizer",
  "scanners": {
    "cisco": {
      "status": "completed",
      "durationMs": 42,
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/cisco.json",
      "isSafe": true,
      "maxSeverity": "SAFE",
      "findingsCount": 0
    },
    "skillspector": {
      "status": "completed",
      "durationMs": 42,
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/skillspector.json",
      "severity": "MEDIUM",
      "score": 31,
      "recommendation": "CAUTION",
      "issues": [
        {
          "id": "LP3",
          "severity": "MEDIUM",
          "file": "SKILL.md"
        },
        {
          "id": "E2",
          "severity": "HIGH",
          "file": "scripts/summarize.py"
        }
      ]
    }
  }
}
```

</details>

## Motivation

Agent-skill security is new and fast-moving, with researchers and companies
exploring many promising scanners, datasets, and judge harnesses. In our
[ClawHub Security Signals paper](https://arxiv.org/html/2606.01494v1), we found
that combining multiple scanners with a configurable judge works better than
relying on any single scanner.

ClawScan turns that approach into a repeatable CLI. It includes a built-in `clawhub` profile, a saved scanner-and-judge configuration that matches what ClawHub runs in production, so researchers can reproduce results, test improvements, and help improve detection against the weekly refreshed ClawHub security-signals dataset.

## Commands

| Command family | Use |
| --- | --- |
| `clawscan <target> --scanner <id>` | Run one or more scanners against an explicit target. Omit `<target>` to scan child skill directories under `./skills`. |
| `clawscan scanners [list\|<scanner-id>]` | Discover supported scanner IDs, required env vars, upstream links, descriptions, and install guidance. |
| `clawscan profiles [-v]` | Inspect built-in profiles; `-v` prints the catalog as YAML. |
| `clawscan benchmark [list\|<benchmark-id>]` | Discover or run supported benchmarks through a selected scanner/profile/judge setup. |
| `clawscan install <scanner-id> [...]` | Install or verify local scanner dependencies where ClawScan has registry-backed install plans. |
