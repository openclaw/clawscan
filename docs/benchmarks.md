# Benchmarks

`clawscan benchmark <benchmark-id>` runs a supported benchmark through the
selected scanners and optional judge harness:

```bash
clawscan benchmark list

clawscan benchmark SkillTrustBench \
  --profile clawhub \
  --output ./artifacts/skilltrustbench-clawhub.json
```

Use `--ids <path-or-url>` with SkillTrustBench to run a fixed subset from a
plain text ID list or JSONL rows with an `id` field. The loader streams the
source (file or HTTP) and accepts at most 5,520 unique IDs, the size of the
pinned SkillTrustBench full set. Each extracted ID may contain at most 256
bytes, and all retained ID text together may contain at most 256 KiB (262,144
bytes). Whitespace around IDs is trimmed. These limits apply to the extracted
IDs, not total source size: the full JSONL list may exceed 256 KiB. Individual
lines must be smaller than the parser's 1 MiB buffer limit.

## Available benchmarks

Hugging Face row requests retry temporary errors up to six attempts and honor
the server's `Retry-After` cooldown, including delays longer than 30 seconds.
Numeric cooldowns beyond Go's duration range saturate at its maximum instead
of wrapping into an immediate retry. Embedded clients can cancel the wait
through `HuggingFaceBenchmarkClient.Context`; CLI users can interrupt the process.

| Benchmark | ID | Source |
| --- | --- | --- |
| ClawHub Security Signals | `clawhub-security-signals` | [Hugging Face](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) |
| SkillTrustBench | `SkillTrustBench` | [Hugging Face](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench) |

## Submitting a patch to the `clawhub` profile

If you are a security researcher who found malicious skills live on ClawHub and
want to improve the production scanner so it catches them, use GitHub private
vulnerability reporting for the sensitive details and open a PR containing only
a candidate `proposals/<GHSA-ID>/clawscan.yml` config. For a guided walkthrough,
ask Codex:

```text
Use $report-clawhub-malicious-skill to walk me through reporting a malicious ClawHub skill.
```

## ClawHub Profile Baseline

Maintainers validate accepted `clawhub` profile proposals against the public
SkillTrustBench leaderboard subset. The maintainer gate writes compact dated
baselines under `benchmarks/skilltrustbench-leaderboard-10pct/`; the latest
`YYYY-MM-DD.json` file is the current accepted baseline.
