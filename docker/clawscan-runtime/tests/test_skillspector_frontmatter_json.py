"""Complete JSON flow values in frontmatter own their structural quotes."""

import pytest

from skillspector.inspection_ledger import LedgerOutcome
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tm
from skillspector.nodes.analyzers import static_runner

TAIL = "ordinary documentation\n" * 400
FRONTMATTER = (
    "---\nname: example\ndescription: ordinary text\n"
    'metadata: {"openclaw": {"requires": {"bins": ["node"]}}}\n---\n'
)


def test_frontmatter_flow_json_does_not_consume_later_documentation():
    source = FRONTMATTER + TAIL
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": source}}, [tm]
    )
    assert result["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


def test_unicode_and_crlf_source_offsets_are_exact():
    from skillspector.frontmatter_json import frontmatter_json_string_spans

    source = FRONTMATTER.replace("ordinary text", "日本語🦞").replace("\n", "\r\n") + TAIL
    spans = frontmatter_json_string_spans(source, lambda: None)
    assert [source[a:b] for a, b in spans] == ['"openclaw"', '"requires"', '"bins"', '"node"']


@pytest.mark.parametrize(
    "source",
    [
        '---\nmetadata: {"requires": ["node"]}\n',
        '---\nmetadata: {"requires": ["node"]}\n---garbage\n',
        'metadata: {"requires": ["node"]}\n',
        '---\nmetadata: {"requires": ["node"]}\ninvalid: [\n---\n',
        "---\nmetadata: {requires: [node]}\n---\n",
        '---\nmetadata: \'{"requires": ["node"]}\'\n---\n',
        '---\nmetadata: |\n  {"requires": ["node"]}\n---\n',
        '---\nmetadata: {"requires": ["node"], "x": .nan}\n---\n',
        '---\nmetadata: &x {"requires": ["node"]}\ncopy: *x\n---\n',
        '---\n!!set\nmetadata: {"requires": ["node"]}\n---\n',
    ],
)
def test_unproven_metadata_gains_no_quote_ownership(source):
    from skillspector.frontmatter_json import frontmatter_json_string_spans

    assert not frontmatter_json_string_spans(source + TAIL, lambda: None)


def test_malicious_command_inside_metadata_keeps_its_finding():
    source = FRONTMATTER.replace('"node"', '"rm -rf /"') + TAIL
    findings = tm.analyze(source, "SKILL.md", "markdown")
    assert any(finding.rule_id == "TM1" for finding in findings)


@pytest.mark.parametrize("constant", ["MAX_FRONTMATTER_JSON_NODES", "MAX_FRONTMATTER_JSON_DEPTH"])
def test_metadata_parser_budget_gains_no_ownership(monkeypatch, constant):
    from skillspector import frontmatter_json

    monkeypatch.setattr(frontmatter_json, constant, 1)
    assert not frontmatter_json.frontmatter_json_string_spans(FRONTMATTER + TAIL, lambda: None)


def test_yaml_constructors_are_never_called(monkeypatch):
    import yaml

    from skillspector.frontmatter_json import frontmatter_json_string_spans

    def forbidden(*args, **kwargs):
        raise AssertionError("Metadata ownership must not construct YAML values")

    monkeypatch.setattr(yaml.SafeLoader, "construct_object", forbidden)
    assert frontmatter_json_string_spans(FRONTMATTER + TAIL, lambda: None)


def test_runtime_deadline_propagates():
    from skillspector.frontmatter_json import frontmatter_json_string_spans

    class DeadlineError(RuntimeError):
        pass

    calls = 0

    def deadline():
        nonlocal calls
        calls += 1
        if calls == 12:
            raise DeadlineError()

    with pytest.raises(DeadlineError):
        frontmatter_json_string_spans(FRONTMATTER + TAIL, deadline)
