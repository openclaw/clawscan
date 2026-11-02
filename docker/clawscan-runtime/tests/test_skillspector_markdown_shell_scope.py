"""Inert Markdown inputs: parse/scan only, never execute shell source."""
import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner

MINIMAL = '"\n```bash\n"$x" -rf /\n: ";"\n```\n'
EXACT = 'Prose "intro\n\n```bash\n"$CMD" -rf /home/victim\necho "end; text"\n#' + 'x' * 5000 + '\n```\n'

def scan(content):
    return static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": content}}, [tool]
    )

@pytest.mark.parametrize("content", [EXACT, MINIMAL])
def test_preceding_prose_cannot_hide_unresolved_fenced_command(content):
    result = scan(content)
    assert result["inspection_ledger"][0]["outcome"] == "partial"

@pytest.mark.parametrize("prefix", ["", 'Prose "intro\n\n'])
def test_benign_owned_body_keeps_completion(prefix):
    result = scan(prefix + '```bash\necho "${VALUE}"\n```\n')
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []

def test_preceding_prose_preserves_literal_destructive_finding():
    result = scan('Prose "intro\n\n```bash\nrm -rf /\n```\n')
    assert any(f.to_dict()["id"] == "TM1" for f in result["findings"])
