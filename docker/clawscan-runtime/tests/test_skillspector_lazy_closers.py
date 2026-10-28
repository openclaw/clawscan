import pytest

from skillspector.nodes.analyzers import static_patterns_agent_snooping, static_runner


@pytest.mark.parametrize('path,parser', [
    ('README.md', 'MarkdownCodeSpanClosers'),
    ('data.csv', 'CSVStringClosers'),
    ('script.py', 'PythonStringClosers'),
])
def test_native_closer_proof_is_not_constructed_without_a_query(monkeypatch, path, parser):
    def unexpected(*args, **kwargs):
        raise AssertionError('native parser was never queried')

    monkeypatch.setattr(static_runner, parser, unexpected)
    findings, reason, _ = static_runner._scan_all_views_detailed(
        path, 'ordinary words\n' * 20, [static_patterns_agent_snooping], None,
    )
    assert findings == []
    assert reason is None


def test_markdown_closer_is_constructed_once_when_real_fallback_queries_it(monkeypatch):
    real = static_runner.MarkdownCodeSpanClosers
    calls = []

    def observed(*args, **kwargs):
        calls.append(args[0])
        return real(*args, **kwargs)

    source = 'Use `drop` to describe a data drop.\nUse `delete` to describe the operation.\n'
    baseline = static_runner._scan_all_views_detailed(
        'README.md', source, [static_patterns_agent_snooping], None,
    )
    monkeypatch.setattr(static_runner, 'MarkdownCodeSpanClosers', observed)
    actual = static_runner._scan_all_views_detailed(
        'README.md', source, [static_patterns_agent_snooping], None,
    )
    assert actual == baseline
    assert calls == [source]
