"""Canonical prose punctuation composes with inline code, cells and lists."""

import pytest

from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner

TAIL = "".join(f"Observation {i}: the interface displays an ordinary result.\n" for i in range(100))
PROSE = [
    "Observe `last_response`'s completed result.\n\n",
    '| Goal | Meaning |\n|---|---|\n| "Match colors" | Observe `color_image` and the route\'s palette fields. |\n\n',
    "- **Hook / pull:** Observe the enemy's neck at `target height`\n"
    "  then follow `the next pose` without moving the canvas.\n\n",
    "Observe v3's `mode=\"pro\"` result and the routes' response.\n\n",
    "## Observe Fiore's guards\n\n",
]


def inspect(source):
    return static_runner.run_static_patterns_with_ledger(
        {"components": ["guide.md"], "file_cache": {"guide.md": source}}, [tool]
    )


@pytest.mark.parametrize("prose", PROSE)
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_composed_prose_completes_without_changing_source_offsets(prose, newline):
    source = ("# Résumé — 比較\n\n" + prose + TAIL).replace("\n", newline)
    lexical = tool._markdown_shell_text(source, lambda: None)
    composed = tool._markdown_shell_text(source, lambda: None, word_apostrophes=True)
    assert len(composed) == len(source)
    changed = [i for i, (a, b) in enumerate(zip(lexical, composed, strict=True)) if a != b]
    assert changed
    assert all(source[i] == "'" and composed[i] == " " for i in changed)
    report = inspect(source)
    assert report["inspection_ledger"][0]["outcome"] == "completed"
    assert report["findings"] == []


@pytest.mark.parametrize("prose", PROSE)
def test_lone_cr_keeps_exact_canonical_origins_without_granting_shell_line_break(prose):
    from skillspector.markdown_tokens import MarkdownCodeSpanClosers

    source = ("# Résumé — 比較\n\n" + prose + TAIL).replace("\n", "\r")
    offsets = MarkdownCodeSpanClosers(
        source, lambda: None, include_tables=True, collect_prose=True
    ).prose_apostrophe_offsets()
    assert offsets
    assert all(source[i] == "'" for i in offsets)
    projected = tool._markdown_shell_text(source, lambda: None, word_apostrophes=True)
    assert all(projected[i] == "'" for i in offsets)


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r", "\u2028"])
@pytest.mark.parametrize("marker", ["- ", "1. ", "## "])
@pytest.mark.parametrize("continuation", ["$CMD \\", "$CMD \\\n\\"])
def test_continued_shell_invocation_retains_prose_operands(newline, marker, continuation):
    source = (
        continuation + "\n" + marker + "Observe the route's `field`.\n"
        "the routes' response -rf /home/victim\n"
    ).replace("\n", newline)
    projected = tool._markdown_shell_text(source, lambda: None, word_apostrophes=True)
    apostrophe = source.index("route's") + len("route")
    assert projected[apostrophe] == "'"
    # A shell heading is a comment, so its apostrophe does not open an operand.
    # List markers do not supply that ownership: retain the complete quoted span.
    if marker != "## ":
        assert projected[source.index("routes'") + len("routes")] == "'"
        report = inspect(source)
        assert report["inspection_ledger"][0]["outcome"] != "completed" or any(
            f.rule_id == "TM1" for f in report["findings"]
        )


@pytest.mark.parametrize("prose", PROSE)
@pytest.mark.parametrize("before", [False, True])
def test_composed_prose_retains_original_threat_locations(prose, before):
    command = "rm -rf /\n"
    source = command + prose + TAIL if before else prose + TAIL + "\n" + command
    report = inspect(source)
    threats = [f for f in report["findings"] if f.rule_id == "TM1"]
    assert threats
    expected = source[: source.index(command)].count("\n") + 1
    assert any(f.start_line == expected for f in threats)


@pytest.mark.parametrize(
    "source",
    [
        "```sh\nObserve the route's `field`.\n```\n\n",
        "    Observe the route's `field`.\n\n",
        "<pre>\nObserve the route's `field`.\n</pre>\n\n",
        "> Observe the route's `field`.\n\n",
        "Observe <span>the route's</span> `field`.\n\n",
        "Observe the route\\'s `field`.\n\n",
        "Observe the route's \\`field\\`.\n\n",
        "Observe the route's ``field ` inner``.\n\n",
        "| Goal | Meaning |\n|---|---|\n| escaped\\|cell | Observe the route's `field`. |\n\n",
        "## Observe $CMD and the route's `field`\n\n",
    ],
)
def test_ambiguous_and_nonprose_contexts_keep_their_apostrophe(source):
    source += TAIL
    projected = tool._markdown_shell_text(source, lambda: None, word_apostrophes=True)
    apostrophe = source.index("route") + len("route")
    if source[apostrophe] == "\\":
        apostrophe += 1
    assert projected[apostrophe] == "'"


@pytest.mark.parametrize(
    "source",
    [
        "$CMD Observe the route's `field`.\nnext' -rf /\n\n",
        'bash -c "\n$CMD -rf /\nObserve the route\'s `field`.\n"\n\n',
        "$(\nObserve the route's `field`.\n') -rf /\n\n",
        "r'\nObserve the route's `field`.\n'm -rf /\n\n",
        "Observe `\"unclosed` before the route's `field`.\n\n",
    ],
)
def test_existing_shell_words_keep_precedence_over_prose_ownership(source):
    source += TAIL
    projected = tool._markdown_shell_text(source, lambda: None, word_apostrophes=True)
    apostrophe = source.index("route's") + len("route")
    assert projected[apostrophe] == "'"
    report = inspect(source)
    assert report["inspection_ledger"][0]["outcome"] != "completed" or any(
        f.rule_id == "TM1" for f in report["findings"]
    )


@pytest.mark.parametrize("prose", PROSE)
def test_composition_needs_complete_markdown_context(prose):
    source = prose + TAIL
    fragment = tool._markdown_shell_text(
        source, lambda: None, word_apostrophes=True, complete_context=False
    )
    assert all(fragment[i] == "'" for i, char in enumerate(source) if char == "'")
    # In a shell, a heading beginning with '#' is already a complete comment.
    if not prose.startswith("#"):
        assert tool.has_bounded_parse_exhaustion(source, lambda: None, file_type="shell")
        assert tool.has_bounded_parse_exhaustion(
            source, lambda: None, file_type="markdown", complete_context=False
        )
