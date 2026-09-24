# Changelog

## Unreleased

- Use GPT-6 Luna with high reasoning for both bundled ClawHub judges and forward SkillSpector model/reasoning and optional A.I.G reasoning settings into scanner sandboxes.

## 0.2.0 - 2026-09-22

**Highlights:** Preserve scanner evidence, bound benchmark input memory, and identify worker-owned containers for cleanup.

- Preserve every scanner report when sanitized target, profile, or custom scanner names collide with each other or generated numeric suffixes (#54).
- Fix unbounded memory use when loading benchmark `--ids` from files or HTTP, including whitespace-padded IDs; document selection limits and preserve full-set JSONL support. Thanks @SebTardif (#47).
- Label worker-owned Docker containers with optional run and command IDs so supervisors can clean up after cancellation. Thanks @jesse-merhi (#55).
- Prevent large Hugging Face `Retry-After` values from overflowing into immediate retries while preserving server cooldowns and cancellation (#58).
- Add `--platform` to build smaller npm tarballs for one supported operating system and architecture while retaining the default universal package. Thanks @vincentkoc (#56).
- Repair contributor links and add the missing scanner-adapter guide. Thanks @atarico for the documentation report (#57).
- Refresh bundled scanner tools and Go dependencies; source builds now require Go 1.27.1, and the Docker runtime uses Node.js 24 LTS (#59).
- Publish changelog-backed release notes with verified npm metadata and show live CI and release status badges.
