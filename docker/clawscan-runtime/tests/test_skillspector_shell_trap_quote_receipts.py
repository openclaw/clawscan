"""Inert shell inputs: parse/scan only, never execute these payloads."""
import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner

EXACT = '```bash\ntrap \'s\\hopt -s expand_aliases; a\\lias a="echo \\""\' DEBUG\n:\nSUFFIX=m\na xxx"\n"r${SUFFIX}" -rf /home/victim\na xxx"\n```\n'
MINIMAL = '```bash\ntrap \'s\\hopt -s expand_aliases; a\\lias a="echo \\""\' DEBUG\nSUFFIX=m\na x"\n"r${SUFFIX}" -rf /home/victim\na x"\n```\n'

def scan(content, path):
    return static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: content}}, [tool]
    )

@pytest.mark.parametrize("command", ["trap", "builtin trap", "command trap", "tr\\ap"])
@pytest.mark.parametrize("path", ["SKILL.md", "example.sh"])
def test_trap_action_cannot_certify_runtime_quote_state(command, path):
    content = EXACT.replace("trap ", command + " ", 1)
    if path.endswith(".sh"):
        content = content[len("```bash\n"):-len("```\n")]
    result = scan(content, path)
    assert result["inspection_ledger"][0]["outcome"] == "partial"

@pytest.mark.parametrize("path", ["SKILL.md", "example.sh"])
def test_minimal_trap_witness_retains_partial(path):
    content = MINIMAL if path.endswith(".md") else MINIMAL[len("```bash\n"):-len("```\n")]
    assert scan(content, path)["inspection_ledger"][0]["outcome"] == "partial"

def test_trap_restriction_preserves_literal_destructive_finding():
    result = scan("```bash\ntrap ':' DEBUG\nrm -rf /\n```\n", "SKILL.md")
    assert any(f.to_dict()["id"] == "TM1" for f in result["findings"])

def test_benign_trap_keeps_straightforward_shell_complete():
    result = scan("```bash\ntrap ':' EXIT\necho okay\n```\n", "SKILL.md")
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []
