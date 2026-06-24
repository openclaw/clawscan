# Artifacts

ClawScan writes JSON artifacts so scanner evidence and judge output can be
reviewed, compared, and attached to reports.

## One-Off Run

A one-off scan writes a `clawscan-run-v1` artifact:

```json
{
  "schemaVersion": "clawscan-run-v1",
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

## Secret Redaction

Artifacts record env var presence only:

```json
"env": {
  "VIRUSTOTAL_API_KEY": "present",
  "SNYK_TOKEN": "missing"
}
```

Do not expect artifacts to contain actual token values, even for failed runs.
