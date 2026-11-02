"""Inert shell text and real pinned-parser receipts; never execute shell inputs."""
import copy
import shutil
import subprocess

import pytest
from skillspector import shell_source
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner

COMPARISON = '[[ "$(printf \'%s\' "$VALUE")" == expected ]]\n'


def ledger(content, path="scripts/example.sh"):
    return static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )


def quoted_nodes(tree):
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if node.get("Type") in {"SglQuoted", "DblQuoted"}:
                yield node
            pending.extend(node.values())


@pytest.fixture
def canonical_parser():
    parser = shutil.which("shfmt")
    assert parser and subprocess.check_output([parser, "--version"], text=True).strip() == "v3.14.1"


@pytest.mark.parametrize("literal", ["$''", "$'ok'", '$""', '$"ok"'])
def test_pinned_dollar_positions_preserve_exact_quote_coordinates(canonical_parser, literal):
    content = '# Résumé 🦀\n: ' + literal + '\necho "${VALUE}"\n'
    tree = shell_source._parse(content.encode(), lambda: None)
    node = next(node for node in quoted_nodes(tree) if node.get("Dollar") is True)
    raw_left = node["Left"]["Offset"]
    assert content.encode()[raw_left:raw_left + 2] == literal[:2].encode()
    owner = shell_source.ShellSourceOwnership(content, lambda: None)
    assert owner.command_starts is not None
    closing = len(content.encode()[:node["Right"]["Offset"]].decode())
    opening = len(content.encode()[:raw_left].decode()) + 1
    assert owner._quote_pairs[closing] == (opening, node["Type"])
    ordinary_end = content.rindex('"')
    assert owner.owns_double_quoted_candidate(content.index("${VALUE}"), ordinary_end)
    assert ordinary_end in owner.quote_closing_offsets()


@pytest.mark.parametrize("suffix", [": $''\n", ": $'ok'\n", ': $""\n', ': $"ok"\n'])
@pytest.mark.parametrize("unicode_prefix", ["", "# Résumé 🦀\n"])
def test_unrelated_dollar_argument_preserves_existing_comparison_roles(canonical_parser, suffix, unicode_prefix):
    result = ledger(unicode_prefix + COMPARISON + suffix)
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []


def test_dollar_assignment_preserves_unrelated_comparison(canonical_parser):
    result = ledger("IFS=$'\\n'\n" + COMPARISON)
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []


@pytest.mark.parametrize("content", [
    "eval $'\\x24CMD -rf /'\n",
    "bash -c $'\\x24CMD -rf /'\n",
    "eval $'\\u0024CMD -rf /'\n",
    "bash -c $'\\u0024CMD -rf /'\n",
    '"$CMD" -rf /\n',
])
def test_unsupported_runtime_values_remain_partial(canonical_parser, content):
    assert ledger(content)["inspection_ledger"][0]["outcome"] == "partial"


def test_dollar_literal_does_not_hide_raw_destructive_finding(canonical_parser):
    result = ledger(": $'ok'\nrm -rf /\n")
    assert any(finding.rule_id == "TM1" and str(finding.severity).upper() == "HIGH"
               for finding in result["findings"])


@pytest.mark.parametrize("flag", [None, 0, 1, "true", [], {}])
def test_malformed_dollar_flags_publish_neither_receipt(canonical_parser, monkeypatch, flag):
    content = ': $\'ok\'\necho "${VALUE}"\n'
    tree = shell_source._parse(content.encode(), lambda: None)
    next(node for node in quoted_nodes(tree) if node.get("Dollar") is True)["Dollar"] = flag
    monkeypatch.setattr(shell_source, "_parse", lambda *_: copy.deepcopy(tree))
    owner = shell_source.ShellSourceOwnership(content, lambda: None)
    assert owner.command_starts is None
    closers = set()
    assert tool._shell_quoted_candidate_limits(content, lambda: None, quote_closers=closers) == {}
    assert closers == set()


@pytest.mark.parametrize("fault", ["prefix-offset", "wrong-delimiter", "utf8-interior", "closing-opener", "closing-eof"])
def test_malformed_dollar_coordinates_retain_fallback(canonical_parser, monkeypatch, fault):
    content = '# 🦀\n: $\'ok\'\necho "${VALUE}"\n'
    tree = shell_source._parse(content.encode(), lambda: None)
    node = next(node for node in quoted_nodes(tree) if node.get("Dollar") is True)
    if fault == "prefix-offset":
        node["Left"]["Offset"] += 1
    elif fault == "wrong-delimiter":
        node["Type"] = "DblQuoted"
    elif fault == "utf8-interior":
        node["Left"]["Offset"] = content.encode().index("🦀".encode()) + 1
    elif fault == "closing-opener":
        node["Right"]["Offset"] = node["Left"]["Offset"] + 1
    else:
        node["Right"]["Offset"] = len(content.encode())
    monkeypatch.setattr(shell_source, "_parse", lambda *_: copy.deepcopy(tree))
    owner = shell_source.ShellSourceOwnership(content, lambda: None)
    assert owner.command_starts is None
    assert owner.quote_closing_offsets() == frozenset()


def test_plain_quotes_accept_an_explicit_false_dollar_flag(canonical_parser, monkeypatch):
    content = 'echo "${VALUE}"\n'
    tree = shell_source._parse(content.encode(), lambda: None)
    next(quoted_nodes(tree))["Dollar"] = False
    monkeypatch.setattr(shell_source, "_parse", lambda *_: copy.deepcopy(tree))
    owner = shell_source.ShellSourceOwnership(content, lambda: None)
    assert owner.command_starts is not None
    assert owner.owns_double_quoted_candidate(content.index("${VALUE}"), content.rindex('"'))
