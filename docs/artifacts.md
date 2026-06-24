# Artifacts

ClawScan writes JSON artifacts so scanner evidence and judge output can be
reviewed, compared, and attached to reports.

## One-Off Run

A one-off scan writes a `clawscan-run-v1` artifact:

```json
{
  "schemaVersion": "clawscan-run-v1",
  "profile": "clawhub",
  "target": {
    "kind": "skill",
    "input": "./my-skill",
    "resolvedPath": "/absolute/path/to/my-skill"
  },
  "startedAt": "2026-06-03T00:00:00Z",
  "completedAt": "2026-06-03T00:00:01Z",
  "env": {
    "VIRUSTOTAL_API_KEY": "present"
  },
  "scanners": {
    "virustotal": {
      "status": "skipped",
      "startedAt": "2026-06-03T00:00:00Z",
      "completedAt": "2026-06-03T00:00:01Z",
      "command": [
        "virustotal",
        "file-report"
      ],
      "error": "VirusTotal scanner supports single-file targets in v1; directory targets are unsupported.",
      "raw": null
    }
  },
  "judge": null
}
```

Scanner `raw` fields preserve upstream scanner JSON as evidence. Scanner
`status` and `error` explain ClawScan's adapter-level outcome.

Consumers should branch on the top-level `schemaVersion` field:

| `schemaVersion` | Meaning |
| --- | --- |
| `clawscan-run-v1` | One normal scan run for one target and one selected profile. |
| `clawscan-batch-v1` | One command wrapping multiple normal run artifacts, such as discovered targets or every profile from `--config <path>`. |
| `clawscan-benchmark-v1` | One benchmark artifact with cases that embed normal run artifacts. |

## Discovered Target Run

When a command discovers multiple child skills under `./skills`, JSON output and
`--output` use a `clawscan-batch-v1` wrapper. Each entry in `runs` is a normal
`clawscan-run-v1` artifact with its own target and raw scanner evidence:

```json
{
  "schemaVersion": "clawscan-batch-v1",
  "profile": "clawhub",
  "runs": [
    {
      "schemaVersion": "clawscan-run-v1",
      "target": {
        "kind": "skill",
        "input": "skills/foo",
        "resolvedPath": "/absolute/path/to/skills/foo"
      }
    },
    {
      "schemaVersion": "clawscan-run-v1",
      "target": {
        "kind": "skill",
        "input": "skills/bar",
        "resolvedPath": "/absolute/path/to/skills/bar"
      }
    }
  ],
  "summary": {
    "targetCount": 2,
    "scannerStatuses": {
      "clawscan-static": {
        "completed": 2
      }
    }
  }
}
```

## Config Profile Batch

When `--config <path>` is passed without `--profile`, ClawScan runs every
profile defined in that config and writes one `clawscan-batch-v1` wrapper. Each
entry in `runs` is a normal `clawscan-run-v1` artifact with its own `profile`:

```json
{
  "schemaVersion": "clawscan-batch-v1",
  "runs": [
    {
      "schemaVersion": "clawscan-run-v1",
      "profile": "clawhub-release",
      "target": {
        "kind": "skill",
        "input": "./my-skill",
        "resolvedPath": "/absolute/path/to/my-skill"
      }
    },
    {
      "schemaVersion": "clawscan-run-v1",
      "profile": "skills-sh-review",
      "target": {
        "kind": "skill",
        "input": "./my-skill",
        "resolvedPath": "/absolute/path/to/my-skill"
      }
    }
  ],
  "summary": {
    "profileCount": 2,
    "targetCount": 1,
    "scannerStatuses": {
      "clawscan-static": {
        "completed": 2
      }
    }
  }
}
```

Passing `--profile <name>` with the same config runs only that profile and keeps
the normal `clawscan-run-v1` artifact shape.

If a profile fails before it can produce a run artifact, the batch includes an
entry in `errors` with the profile name and error message.

## Benchmark Run

A benchmark run writes a `clawscan-benchmark-v1` artifact:

```json
{
  "schemaVersion": "clawscan-benchmark-v1",
  "benchmark": {
    "id": "cuhk-zhuque/SkillTrustBench",
    "source": "huggingface",
    "config": "default",
    "split": "benchmark",
    "offset": 0,
    "limit": 1,
    "rows": 1
  },
  "startedAt": "2026-06-03T00:00:00Z",
  "completedAt": "2026-06-03T00:00:01Z",
  "env": {},
  "cases": [
    {
      "id": "case_04866",
      "skillSlug": "case_04866",
      "skillVersion": "v1.0",
      "expected": {
        "verdict": "malicious",
        "summary": "SkillTrustBench judgment: malicious; category: devtool; primary pattern: E2; source: injected",
        "context": {
          "risk_labels": ["T04", "T05"],
          "source": "injected",
          "base_category": "devtool",
          "primary_pattern": "E2",
          "attack_pattern": ["E2", "E1", "PE3", "SC1"],
          "skill_path": "benchmark_full_v1.0/case_04866"
        }
      },
      "run": {
        "schemaVersion": "clawscan-run-v1"
      }
    }
  ],
  "summary": {
    "caseCount": 1,
    "expectedVerdicts": {
      "malicious": 1
    },
    "scannerStatuses": {
      "clawscan-static": {
        "completed": 1
      }
    }
  }
}
```

Each benchmark case embeds a normal `clawscan-run-v1` artifact under `run`.

OpenClaw security-signals benchmark runs also produce a lightweight
`predictions.jsonl` submission file when `--output` or `--predictions-output` is
used:

```json
{"id":"clean-case","prediction":"clean"}
{"id":"suspicious-case","prediction":"suspicious"}
{"id":"malicious-case","prediction":"malicious"}
```

The benchmark artifact keeps the full scanner and judge evidence. The
predictions file keeps only the case ID and submitted verdict for leaderboard
validation and scoring.

Benchmark cases also include benchmark-only evaluation metadata when ClawScan
can map the expected label and prediction into the canonical verdicts `clean`,
`suspicious`, and `malicious`.

## Secret Redaction

Artifacts record env var presence only:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Do not expect artifacts to contain actual token values, even for failed runs.
