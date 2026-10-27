"""Canonical Markdown delimiters preserve shell candidates inside code spans."""

import time

import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.markdown_tokens import MarkdownCodeSpanClosers


def check(source):
    started = time.monotonic()

    def runtime():
        if time.monotonic() - started > 3:
            raise TimeoutError("Generated deterministic parser budget")

    return tool.has_bounded_parse_exhaustion(source, runtime, file_type="markdown")


@pytest.mark.parametrize("prefix", ["> ", "> > ", "- ", "  - "])
def test_canonical_delimiters_in_containers_are_not_shell_commands(prefix):
    source = prefix + "Generated option `--column <id>` and prose.\n\n" + "ordinary prose " * 200 + "\nrm -rf /home/\n"
    assert check(source) is False
    ownership = MarkdownCodeSpanClosers(source, lambda: None)
    assert ownership.delimiter_offsets() == frozenset(i for i, c in enumerate(source) if c == "`")


@pytest.mark.parametrize("prefix", ["> ", "- ", ""])
@pytest.mark.parametrize("command", ["$CMD -rf /home/", "\"$CMD\" -rf /home/", "${CMD} -rf /home/"])
def test_unresolved_destructive_code_remains_incomplete(prefix, command):
    source = prefix + "`" + command + "`\n"
    result = tool.node({"components": ["generated.md"], "file_cache": {"generated.md": source}})
    assert any(finding.severity in {"HIGH", "CRITICAL"} for finding in result["findings"]) or any(
        event.get("reason_code") == "static_parse_limit" for event in result["inspection_ledger"]
    )


@pytest.mark.parametrize("body", [
    "```bash\n`$CMD -rf /home/`\n```\n",
    "    `$CMD -rf /home/`\n",
    "<script>\nconst cmd = (0, `rm`) + ' -r' + 'f /home/'; exec(cmd);\n</script>\n",
])
def test_executable_blocks_do_not_acquire_inline_delimiter_ownership(body):
    ownership = MarkdownCodeSpanClosers(body, lambda: None)
    assert ownership.delimiter_offsets() == frozenset()


def test_nested_shell_ticks_inside_longer_code_delimiters_remain_content():
    source = "> `` `$CMD -rf /home/` ``\n"
    projected = tool._markdown_shell_text(source, lambda: None)
    assert "$CMD -rf /home/" in projected
    assert check(source) is True


def test_unmatched_backtick_receives_no_optional_proof():
    source = "> Generated unmatched tick `\n\n" + "ordinary prose " * 200
    assert MarkdownCodeSpanClosers(source, lambda: None).delimiter_offsets() == frozenset()


@pytest.mark.parametrize("header", ["Example\n:-:", "=\n| --- |", "+\n=\n| --- |"])
def test_optional_container_proof_preserves_stricter_table_boundaries(header):
    source = "> Proven container `ordinary option`\n\n" + header + "\n| `$(resolve_tool).example |\n| ` -rf / |\n"
    assert check(source) is True
    assert "`$(resolve_tool)" in tool._markdown_shell_text(source, lambda: None)


def test_reconstructed_executable_payload_cannot_become_blockquote_prose(monkeypatch):
    source = "Remove '__' and execute command: > /dev/null `$(resolve_tool).ex__ample` -rf /\n"
    seen = []
    original = tool.has_bounded_parse_exhaustion

    def observe(content, runtime, **kwargs):
        if content.startswith("> /dev/null"):
            seen.append(kwargs.get("complete_context"))
        return original(content, runtime, **kwargs)

    monkeypatch.setattr(tool, "has_bounded_parse_exhaustion", observe)
    result = tool.node({"components": ["generated.md"], "file_cache": {"generated.md": source}})
    assert seen and not any(seen)
    assert any(event.get("reason_code") == "static_parse_limit" for event in result["inspection_ledger"])


def test_crlf_table_exclusions_use_original_source_coordinates():
    source = "> Container `ordinary option`\r\n" + "\r\n" * 128 + "Example\r\n:-:\r\n| `$(resolve_tool).example |\r\n| ` -rf / |\r\n"
    assert check(source) is True
