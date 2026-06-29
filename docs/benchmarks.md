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
plain text ID list or JSONL rows with an `id` field.

## Available benchmarks

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
SkillTrustBench leaderboard subset. The latest accepted compact baseline is
written by the maintainer gate to
`benchmarks/skilltrustbench-leaderboard-10pct/clawhub-baseline.json`.
