"""Local literal ownership never spends a shell budget on later prose."""

import pytest

from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner

TAIL = "\n\n" + "An ordinary observation.\n" * 180


def inspect(source):
    return static_runner.run_static_patterns_with_ledger(
        {"components": ["guide.md"], "file_cache": {"guide.md": source}}, [tool]
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "container", ["Use {code}.", "- Use {code}.", "> Use {code}.", "| Example |\n|---|\n| {code} |"]
)
def test_complete_inline_json_has_structural_quote_ownership(newline, container):
    source = (container.format(code='`{"event": "ok", "reason": "ordinary"}`') + TAIL).replace(
        "\n", newline
    )
    result = inspect(source)
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []


@pytest.mark.parametrize(
    "source",
    [
        'Use `{"event": "ok"`.',
        "Use `quickFlags()``.",
        "```sh\n`/api/${id}\n```",
        'Use `{"event": NaN}`.',
        'Use `{"event": "ok"} trailing`.',
    ],
)
def test_unproven_or_incomplete_local_ownership_stays_partial(source):
    result = inspect(source + TAIL)
    assert result["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("before", [False, True])
@pytest.mark.parametrize(
    "source",
    [
        'Use `{"event": "ok"}`.\n',
    ],
)
def test_local_ownership_preserves_independent_destructive_command_locations(source, before):
    command = "rm -rf /\n"
    content = command + source + TAIL if before else source + TAIL + command
    result = inspect(content)
    findings = [f for f in result["findings"] if f.rule_id == "TM1"]
    assert findings
    expected_line = content[: content.index(command)].count("\n") + 1
    assert any(f.start_line == expected_line for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        'Use `{"event": "$(resolve_tool) -rf /"}`.\n',
        "```sh\n`echo /api/${id}; $(resolve_tool) -rf /`\n```\n",
        "```sh\n`echo /api/${id}` -rf /\n```\n",
        "```sh\n`echo /api/${id}; " + "r" * 4097 + "`\n```\n",
    ],
)
def test_executable_nested_or_outer_commands_keep_uncertainty(source):
    result = inspect(source + TAIL)
    assert result["inspection_ledger"][0]["outcome"] != "completed" or any(
        f.rule_id == "TM1" for f in result["findings"]
    )


@pytest.mark.parametrize(
    "prefix,suffix",
    [
        ('bash -c "\n', '\n"'),
        ("$CMD \\\n", ""),
        ("r'\n", "'m -rf /"),
    ],
)
def test_inline_json_does_not_terminate_existing_shell_execution(prefix, suffix):
    source = prefix + 'Use `{"event": "$(resolve_tool) -rf /"}`.' + suffix + TAIL
    result = inspect(source)
    assert result["inspection_ledger"][0]["outcome"] != "completed" or any(
        f.rule_id == "TM1" for f in result["findings"]
    )
