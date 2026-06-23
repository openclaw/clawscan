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
    "id": "OpenClaw/clawhub-security-signals",
    "source": "huggingface",
    "config": "default",
    "split": "eval_holdout",
    "offset": 0,
    "limit": 1,
    "rows": 1
  },
  "startedAt": "2026-06-03T00:00:00Z",
  "completedAt": "2026-06-03T00:00:01Z",
  "env": {},
  "cases": [
    {
      "id": "dataset-row-id",
      "skillSlug": "owner/skill",
      "skillVersion": "1.0.0",
      "expected": {
        "verdict": "suspicious",
        "confidence": "high",
        "model": "gpt-5.5",
        "summary": "Dataset verdict summary."
      },
      "run": {
        "schemaVersion": "clawscan-run-v1"
      }
    }
  ],
  "summary": {
    "caseCount": 1,
    "expectedVerdicts": {
      "suspicious": 1
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
