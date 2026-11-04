"""aig-mcp-scan static audits must not give the LLM agent a shell or file writes.

The agent reads untrusted plugin code, so prompt injection in that code must not
reach command execution in the scanner environment. Run with the aig-mcp-scan
tool environment's Python after applying aig-mcp-static-tools.patch.
"""

import asyncio
import os

import pytest


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    # aig-mcp-scan's logger creates logs/ in the working directory on import.
    monkeypatch.chdir(tmp_path)


def dispatcher(server_url=None):
    import mcp_scan.tools  # noqa: F401  registers the bundled tools
    from mcp_scan.tools.dispatcher import ToolDispatcher

    return ToolDispatcher(mcp_server_url=server_url)


def test_static_prompt_offers_only_read_tools():
    from mcp_scan.tools.registry import get_tool_names

    assert "execute_shell" in get_tool_names(), "upstream tool set changed; re-review the patch"
    prompt = asyncio.run(dispatcher().get_all_tools_prompt())
    assert 'name="read_file"' in prompt
    assert 'name="finish"' in prompt
    assert "execute_shell" not in prompt
    assert "write_file" not in prompt


@pytest.mark.parametrize(
    "tool, args",
    [
        ("execute_shell", {"command": "touch pwned"}),
        ("write_file", {"file_path": "pwned", "content": "x"}),
    ],
)
def test_static_calls_to_blocked_tools_do_nothing(tool, args, tmp_path):
    result = asyncio.run(dispatcher().call_tool(tool, args))
    assert f"Tool '{tool}' is not available in static scan mode" in result
    assert not os.path.exists(tmp_path / "pwned")


def test_read_file_still_works_inside_the_audited_directory(tmp_path):
    from mcp_scan.utils.tool_context import ToolContext

    (tmp_path / "plugin").mkdir()
    (tmp_path / "plugin" / "index.js").write_text("export {};\n")
    context = ToolContext.__new__(ToolContext)
    context.folder = str(tmp_path / "plugin")
    inside = asyncio.run(dispatcher().call_tool("read_file", {"file_path": str(tmp_path / "plugin" / "index.js")}, context))
    assert "export {};" in inside
    outside = asyncio.run(dispatcher().call_tool("read_file", {"file_path": "/etc/hosts"}, context))
    assert "Path is not allowed" in outside
