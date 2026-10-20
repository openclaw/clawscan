---
name: autoreview
description: Structured code review through the shared OpenClaw agent-skills installation.
---

# Auto Review

Use the canonical [autoreview skill](https://github.com/openclaw/agent-skills/tree/main/skills/autoreview).
Read the complete installed `~/.agents/skills/autoreview/SKILL.md` and the references
it requires before reviewing. If installed at another operator-selected location,
use that installation. This repository entrypoint contains no review implementation.

If the skill is missing, reuse or clone `https://github.com/openclaw/agent-skills`
and run `python3 scripts/install-skills autoreview` from that checkout. On Windows,
use `python`; `--mode copy` is available when symlinks are unavailable.

Run the shared `scripts/autoreview` helper with Python from the repository being
reviewed, preserving its working directory. Follow this repository's review
requirements in addition to the canonical skill.

For this repository, default to GPT-6.1 Sol with high reasoning and Standard
service. Preserve an explicit user-selected engine, model, effort, or service tier.
The example below is **only for an otherwise-unconfigured Codex route**. CLI
flags override environment defaults; do not blindly append these flags when a
user or operator has selected another value. Apply defaults independently:

- Engine: honor an explicit user choice or `AUTOREVIEW_ENGINE`; otherwise Codex.
- Model: omit the repository `--model` default when an explicit choice,
  `AUTOREVIEW_CODEX_MODEL`, or `AUTOREVIEW_MODEL` selects it.
- Effort: omit the repository `--thinking` default when an explicit choice,
  `AUTOREVIEW_CODEX_THINKING`, `AUTOREVIEW_THINKING`, or an explicit Codex
  `model_reasoning_effort` config override selects it.
- Tier: omit `--codex-speed default` when an explicit speed/tier choice,
  `AUTOREVIEW_CODEX_SPEED`, or a `service_tier` override in `--codex-config` /
  `AUTOREVIEW_CODEX_CONFIG` selects it. Preserve that explicit override.

Pass user-selected CLI values as requested; otherwise omit the corresponding
flag so the helper can read its supported environment/config setting. Add only
missing Codex defaults. For a non-Codex engine, do not project Codex-specific
model/effort/tier defaults onto it.

With no such choices or environment overrides, run:

```bash
python3 "$HOME/.agents/skills/autoreview/scripts/autoreview" \
  --engine codex --model gpt-6.1-sol --thinking high --codex-speed default \
  --max-priority P3 --mode local
```

Use `--mode branch --base origin/main` for the committed branch review.

Keep shared fixes and instructions upstream in `openclaw/agent-skills`. Update
the shared checkout once for all symlinked consumers; reinstall copy-mode skills
after updating their source. Do not add repository-local helpers or test copies.
