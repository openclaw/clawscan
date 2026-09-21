# Changelog

## Unreleased

- Add `--platform` to build smaller npm tarballs for one supported operating system and architecture while retaining the default universal package.
- Preserve every scanner report when sanitized target, profile, or custom scanner names collide with each other or generated numeric suffixes.
- Fix unbounded memory use when loading benchmark `--ids` from files or HTTP, including whitespace-padded IDs; document selection limits and preserve full-set JSONL support. Thanks @SebTardif (#47).
