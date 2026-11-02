"""Closed shell fences own quotes without borrowing later JSON operands."""

import pytest

from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner


HEADER_JSON_SOURCE = '```bash\nclient mcp add example \\\n  --transport streamable-http \\\n  --url https://example.test/api/mcp \\\n  --header "Authorization=Bearer ${EXAMPLE_API_KEY}" \\\n  --header "X-Example-Agent-Platform=client"\n```\n\n```json\n{\n  "mcp": {\n    "servers": {\n      "example": {\n        "transport": "streamable-http",\n        "url": "https://example.test/api/mcp",\n        "headers": {\n          "Authorization": "Bearer ${EXAMPLE_API_KEY}",\n          "X-Example-Agent-Platform": "client"\n        }\n      }\n    }\n  }\n}\n```\n'
SHADOWED_UNDEFINED_BROWSER_SOURCE = 'from pathlib import Path\nfrom html import escape\nimport json\ndef render(data):\n    payload = json.dumps(data).replace(\'</\', \'<\\\\/\')\n    label = escape(data[\'label\'])\n    return f\'\'\'<!doctype html><html><body><p>{label}</p><div id="panel"></div><script id="data" type="application/json">{payload}</script><script>\nconst data = JSON.parse(document.getElementById(\'data\').textContent);\nconst panel = document.getElementById(\'panel\');\nconst rows = data.items;\nfunction escapeText(value) {{\n  return String(value ?? \'\').replaceAll(\'&\', \'&amp;\').replaceAll(\'<\', \'&lt;\')\n    .replaceAll(\'>\', \'&gt;\').replaceAll(\'"\', \'&quot;\');\n}}\nfunction listMarkup(items, emptyText=\'None\') {{\n  if (!items || !items.length) {{\n    return `<div class="empty">${{escapeText(emptyText)}}</div>`;\n  }}\n  return `<ul>${{items.map((item) => `<li>${{escapeText(typeof item === \'string\' ? item : JSON.stringify(item))}}</li>`).join(\'\')}}</ul>`;\n}}\nfunction renderList(undefined) {{\npanel.innerHTML = `<section>${{listMarkup(undefined.map((item) => `${{item.name}} :: ${{item.value}}`))}}</section>`;\n}}\nrenderList(external);</script></body></html>\'\'\'\nPath(\'page.html\').write_text(render(data), encoding=\'utf-8\')\n'

def source():
    return HEADER_JSON_SOURCE


def ledger(content, path="SKILL.md"):
    return static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("prefix", ["", "# Configuration 👋\n\n"])
def test_closed_shell_quote_does_not_consume_later_json(newline, prefix):
    result = ledger((prefix + source() + "\nFollow-up → ordinary text.\n").replace("\n", newline))
    # CRLF bodies require a byte-exact shell/Markdown receipt; normalization
    # does not establish one. Retain partial coverage until it is attested.
    expected = "completed" if newline == "\n" else "partial"
    assert result["inspection_ledger"][0]["outcome"] == expected
    assert result["findings"] == []


def test_quote_proof_and_bounded_reparse_are_both_required(monkeypatch):
    original = tool._shell_quoted_candidate_limits

    def no_limits(content, check_runtime, *, quote_closers=None):
        original(content, check_runtime, quote_closers=quote_closers)
        return {}

    monkeypatch.setattr(tool, "_shell_quoted_candidate_limits", no_limits)
    assert ledger(source())["inspection_ledger"][0]["outcome"] == "partial"
    monkeypatch.setattr(tool, "_shell_quoted_candidate_limits", lambda *a, **k: {})
    assert ledger(source())["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("opening", ["```", "```json", "```BASH", "```bash extra", "> ```bash", "- ```bash"])
def test_unproven_markdown_does_not_supply_shell_quote_ranges(opening):
    ranges = []
    tool._markdown_shell_text(
        opening + '\necho "${VALUE}"\n```\n', lambda: None, shell_fence_ranges=ranges
    )
    assert ranges == []


@pytest.mark.parametrize("complete,closer", [(False, "```"), (True, "``"), (True, "~~~"), (True, "")])
def test_incomplete_fences_do_not_supply_quote_ranges(complete, closer):
    ranges = []
    tool._markdown_shell_text(
        '```bash\necho "${VALUE}"\n' + closer, lambda: None,
        complete_context=complete, shell_fence_ranges=ranges,
    )
    assert ranges == []


@pytest.mark.parametrize("command", [
    '"$CMD" -rf /',
    'echo "$("$CMD" -rf /)"',
    'bash -c \'"$CMD" -rf /\'',
    'echo "x: $(printf %s r m) -rf /"',
    'bash -c "$SCRIPT"',
])
def test_dynamic_shell_remains_partial(command):
    assert ledger("```bash\n" + command + "\n```\n" + source())["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("command", ["rm -rf /", 'echo "$(r"m" -rf /*)"', 'sh -c ":; r""m -rf /*"'])
def test_literal_destructive_commands_keep_high_findings(command):
    result = ledger("```bash\n" + command + "\n```\n" + source())
    assert any(f.rule_id == "TM1" and str(f.severity).upper() == "HIGH" for f in result["findings"])


@pytest.mark.parametrize("content", [
    'echo "unterminated',
    'echo "$(unclosed',
    'echo "line one\n${VALUE}"\n',
    'echo "`unknown` ${VALUE}"\n',
    "$(" * 34 + 'echo "${VALUE}"' + ")" * 34,
])
def test_unproven_or_multiline_quotes_publish_no_candidate_limits(content):
    assert tool._shell_quoted_candidate_limits(content, lambda: None) == {}


@pytest.mark.parametrize("body", [
    "cat <<END\nbody\nEND\n",
    "cat <<'END'\nbody\nEND\n",
    'cat <<<"$VALUE"\n',
    "$(cat <<" + " " * 4097 + "END\n)\nEND\n)",
    "$(cat <<" + "\t" * 4097 + "END\n)\nEND\n)",
])
def test_heredocs_keep_pinned_parser_path(body):
    # #948 also updates substitution parsing. That separate dependency is
    # excluded: these fences publish no optional quote proof, even if an
    # earlier ordinary quote could otherwise be refined.
    closers = set()
    content = 'echo "${VALUE}"\n' + body
    assert tool._shell_quoted_candidate_limits(content, lambda: None, quote_closers=closers) == {}
    assert closers == set()


@pytest.mark.parametrize("exception", [TimeoutError, RuntimeError])
def test_quote_proof_propagates_cancellation(exception):
    def cancel():
        raise exception("caller cancelled")

    with pytest.raises(exception, match="caller cancelled"):
        tool.has_bounded_parse_exhaustion(source(), cancel, file_type="markdown")


def test_shadowed_undefined_unknown_browser_receiver_remains_partial():
    # Exact #948/643d912 review counterexample: its browser projection is not
    # part of this shell-only compatibility backport. This program is data.
    content = SHADOWED_UNDEFINED_BROWSER_SOURCE
    result = ledger(content, "scripts/page.py")
    assert result["inspection_ledger"][0]["outcome"] == "partial"


def test_single_quotes_and_escaped_double_quotes_preserve_source_offsets():
    text = 'echo \'"opaque"\'; echo "prefix \\" ${VALUE}"\n'
    closers = set()
    limits = tool._shell_quoted_candidate_limits(text, lambda: None, quote_closers=closers)
    assert limits[text.index("${VALUE}")] == text.rindex('"')
    assert text.index("'", text.index("'") + 1) in closers


# Reviewer counterexamples are inert input data; no shell program is executed.
@pytest.mark.parametrize("content", [
    '```bash\nCMD=rm\nshopt -s expand_aliases\nalias launch=eval\nlaunch "X=foo $CMD" -rf /*\n#' + 'x' * 5000 + '\n\n```\n',
    '```bash\nshopt -s expand_aliases\nSUFFIX=m\nalias a=\'echo "\'\na xxx"\n"r${SUFFIX}" -rf /home/victim\na xxx"\n```\n',
    '```bash\nSUFFIX=m\n#\rxxx"\n"r${SUFFIX}" -rf /home/victim\n#\rxxx"\n\n```\n',
    '```bash\nmkdir -p x=\n"x=/${TOOL}" -rf /home/victim\n#' + 'x' * 5000 + '\n\n```\n',
    '```bash\necho "X= ${VALUE}"; "$CMD" -rf /data; echo "' + 'A' * 4097 + '"\n```\n',
    '```sh\nTOOL=rm\n# \'\n"$TOOL" -rf /workspace\necho \'ok \'\n#' + 'x' * 5000 + '\n\n```\n',
    '```bash\nCMD=rm\nclient --header "Authorization=Bearer ${API_KEY}"\n$CMD -rf /data\necho "ok next"\n```\n',
    '```bash\nshopt -s expand_aliases\nalias run=eval\nrun :" ; $CMD" -rf /*\n#' + 'x' * 5000 + '\n\n```\n',
    'Prose "intro\n~~~bash\n"/opt/my tools/$CMD" -rf /\n~~~\n' + 'x' * 5000 + '',
    '```bash\necho "X= ${VALUE}"\n"$CMD" -rf /\necho "end text"\n```\n',
    '```bash\n/bin"/$CMD" -rf /\n#' + 'x' * 5000 + '\n\n```\n',
    '```bash\nCMD=rm\n# "\necho "prefix $LABEL"\n"$CMD" -rf /* # "' + 'a' * 4097 + '\n```\n',
    '```bash\necho x"prefix $VALUE"\n$CMD -rf /\necho " tail"\n```\n',
], ids=['f01-alias-eval', 'f02-alias-lexical', 'f03-cr-comment', 'f05-outer-path', 'f06-word-limit-frontier', 'f07-comment-frontier', 'f08-header-frontier', 'f09-alias-reparser', 'f10-prose-path', 'f11-simple-frontier', 'f12-spliced-path', 'f13-comment-limit-frontier', 'f14-prefix-frontier'])
def test_quote_refinement_does_not_hide_unresolved_commands(content):
    result = ledger(content)
    assert result["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("content", [
    '```bash\nshopt -s expand_aliases\nalias q=eval\nq "X= $C" -rf /\n#' + 'x' * 4081 + '\n```\n',
    '```bash\n#\rx"\n"r${S}" -rf /\n#\rx"\n```\n',
    '```bash\n/bin"/$C" -rf /\n#' + 'x' * 4081 + '\n```\n',
    '```bash\n: "X= $V"\n$C -rf /\n: " "\n```\n',
], ids=['minimal-alias', 'minimal-cr', 'minimal-spliced-path', 'minimal-frontier'])
def test_minimized_quote_ownership_failures_remain_partial(content):
    assert ledger(content)["inspection_ledger"][0]["outcome"] == "partial"
