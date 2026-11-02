"""Inert scanner fixtures; none of the shell source is executed."""
import pytest

from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner


def test_unproved_comment_frontier_preserves_runtime_command_gap():
    content = '```\nCMD=rm\n: x\\ # "\n"; "$CMD" -rf /home/victim; : "\n: x\\ # "\n```\n'
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("prefix", [": x\\ # ", ": x # ", ": x\t# ", ": x\xa0# "])
@pytest.mark.parametrize("fence", ["", "bash", "sh", "python", None])
def test_comment_and_fence_context_cannot_clear_unproved_frontier(prefix, fence):
    body = 'CMD=rm\n' + prefix + '"\n"; "$CMD" -rf /home/victim; : "\n' + prefix + '"\n'
    content = body if fence is None else "```" + fence + "\n" + body + "```\n"
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "partial"


@pytest.mark.parametrize("content", [
    '```\nCMD=echo\n: x\\ # "\n"; "$CMD"; : "\n: x\\ # "\n```\n',
    '```bash\necho "${VALUE}"\n```\n',
])
def test_frontier_repair_preserves_completed_benign_controls(content):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert result["findings"] == []


def test_frontier_repair_preserves_raw_destructive_finding():
    content = '```bash\nrm -rf /\n```\n'
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["SKILL.md"], "file_cache": {"SKILL.md": content}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
    assert any(finding.to_dict()["id"] == "TM1" for finding in result["findings"])
