import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner


def test_quoted_prose_containing_command_word_is_fully_inspected():
    path = "example.json"
    result = static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: '{"x":"a del b"}'}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result.get("findings", []) == []


def test_quoted_shell_data_containing_command_word_is_fully_inspected():
    path = "example.sh"
    result = static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: 'echo "a del b"'}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result.get("findings", []) == []


@pytest.mark.parametrize("path,content", [
    ("example.md", '"a del b"'),
    ("example.json", '{"x":"a rm b"}'),
    ("example.json", '{"x":"a erase b"}'),
])
def test_balanced_literal_quotes_retain_inner_word_inspection(path,content):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result.get("findings", []) == []


@pytest.mark.parametrize("path,content", [
    ("example.sh", 'rm -rf /*'),
    ("example.sh", 'sh -c "a; rm -rf /*"'),
    ("example.sh", "sh -c 'a; rm -rf /*'"),
    ("example.json", '{"x":"a rm -rf /*"}'),
])
def test_destructive_commands_inside_quoted_text_retain_high_findings(path,content):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )
    assert any(f.rule_id == "TM1" and str(f.severity).upper() == "HIGH"
               for f in result["findings"])


@pytest.mark.parametrize("path,content", [
    ("example.sh", 'payload="a rm -rf /"; eval "$payload"'),
    ("example.sh", '"$CMD" -rf /'),
    ("example.sh", 'del "unterminated'),
    ("example.json", '{"x":"a del b"'),
    ("example.sh", 'echo "a del ' + 'x ' * 5000 + 'b"'),
])
def test_unknown_consumers_malformed_quotes_and_span_limits_remain_partial(path,content):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("padding", [0, 6000])
def test_reconstructed_destructive_command_retains_parse_uncertainty(padding):
    source = 'echo "x: $(printf %s r m) -rf /"\n# ' + "." * padding + "\n"
    assert tool.has_bounded_parse_exhaustion(source, lambda: None, file_type="shell")
