"""Generated-only controls for bounded MCP applicability after the call budget."""

import asyncio
import hashlib
import json
import socket

import httpx
import pytest
from skillspector.nodes.analyzers import mcp_tool_poisoning as mcp
from skillspector.providers.openai import OpenAIProvider


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "inert-not-a-credential")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("SKILLSPECTOR_PROVIDER", "openai")
    monkeypatch.setenv("SKILLSPECTOR_REASONING_EFFORT", "medium")
    monkeypatch.setenv("SKILLSPECTOR_SERVICE_TIER", "default")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    monkeypatch.delenv("SKILLSPECTOR_SEED", raising=False)
    observed = {"requests": [], "prefixes": [], "fences": [], "error": False}
    original_prefix = mcp._bounded_utf8_prefix
    original_fences = mcp._iter_tp4_markdown_fences

    def deny_network(*args, **kwargs):
        raise AssertionError("Generated controls must not access the network")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)

    def prefix(content, max_bytes):
        retained, size, truncated = original_prefix(content, max_bytes)
        observed["prefixes"].append((hashlib.sha256(retained.encode()).hexdigest(), size))
        return retained, size, truncated

    def fences(content):
        observed["fences"].append(hashlib.sha256(content.encode()).hexdigest())
        return original_fences(content)

    def response(request):
        body = json.loads(request.content)
        assert request.url.host == "127.0.0.1"
        assert request.url.path == "/v1/responses"
        assert body["model"] == "gpt-6.1-sol"
        assert body["reasoning"] == {"effort": "medium"}
        assert body["service_tier"] == "default"
        observed["requests"].append(body)
        if observed["error"]:
            return httpx.Response(400, request=request, json={"error": {
                "type": "invalid_request_error", "message": "Generated permanent failure"}})
        mismatch = "GENERATED_FINDING" in json.dumps(body["input"])
        payload = {"is_mismatch": mismatch, "confidence": 0.99,
                   "mismatched_capabilities": ["Generated undeclared capability"],
                   "explanation": "Generated fixture only"}
        return httpx.Response(200, request=request, json={
            "id": "resp_generated", "object": "response", "created_at": 1,
            "status": "completed", "model": "gpt-6.1-sol", "parallel_tool_calls": True,
            "tool_choice": "auto", "tools": [], "output": [{
                "type": "message", "id": "msg_generated", "role": "assistant",
                "status": "completed", "content": [{"type": "output_text",
                    "text": json.dumps(payload), "annotations": []}]}],
            "usage": {"input_tokens": 12, "output_tokens": 7, "total_tokens": 19}})

    def send(client, request, **kwargs):
        return response(request)

    async def asend(client, request, **kwargs):
        await asyncio.sleep(0)
        return response(request)

    probe = OpenAIProvider().create_chat_model("gpt-6.1-sol", max_tokens=256)
    monkeypatch.setattr(type(probe.root_client._client), "send", send)
    monkeypatch.setattr(type(probe.root_async_client._client), "send", asend)
    monkeypatch.setattr(mcp, "_bounded_utf8_prefix", prefix)
    monkeypatch.setattr(mcp, "_iter_tp4_markdown_fences", fences)
    return observed


def state_for(files):
    return {"manifest": {"description": "Generated local documentation."},
            "file_cache": files, "components": list(files), "use_llm": True,
            "component_metadata": [{"path": path, "type": "python" if path.endswith(".py")
                                    else "markdown"} for path in files],
            "model_config": {"default": "gpt-6.1-sol"}}


def executable_files(count=64):
    return {f"fixture-{index:03}.py": "print('generated inert fixture')\n"
            for index in range(count)}


@pytest.mark.parametrize("prose_count", [1, 2, 64])
def test_call_budget_does_not_prevent_bounded_applicability(transport, prose_count):
    files = executable_files()
    prose = {f"prose-{index:03}.md": f"Generated inert prose {index}.\n"
             for index in range(prose_count)}
    files.update(prose)
    result = mcp.node(state_for(files))
    assert len(transport["requests"]) == mcp.TP4_MAX_BATCHES == 64
    assert len(transport["prefixes"]) == len(files)
    assert sum(size for _, size in transport["prefixes"]) == sum(
        len(content.encode()) for content in files.values())
    assert transport["fences"] == [hashlib.sha256(content.encode()).hexdigest()
                                   for content in prose.values()]
    assert result["analyzer_status_events"][0]["status"] == "completed"
    assert len(result["inspection_ledger"]) == 65


def test_late_applicable_content_is_still_partial(transport):
    files = executable_files()
    files["prose.md"] = "Generated inert prose.\n"
    files["late.md"] = "```python\nprint('GENERATED_FINDING')\n```\n"
    result = mcp.node(state_for(files))
    assert len(transport["requests"]) == 64
    assert len(transport["prefixes"]) == 66
    assert result["analyzer_status_events"][0]["status"] == "degraded"
    assert any(event["path"] == "late.md" and event.get("reason_code") == "output_limit"
               for event in result["inspection_ledger"])
    assert not result["findings"]


@pytest.mark.parametrize("count", [65, 66, 67, 129])
def test_genuinely_applicable_over_budget_remains_partial(transport, count):
    result = mcp.node(state_for(executable_files(count)))
    assert len(transport["requests"]) == 64
    assert result["analyzer_status_events"][0]["status"] == "degraded"
    assert any(event.get("reason_code") == "output_limit"
               for event in result["inspection_ledger"])


@pytest.mark.parametrize("boundary", ["file", "total", "artifacts", "runtime"])
def test_applicability_limits_remain_fail_closed(monkeypatch, transport, boundary):
    files = executable_files()
    if boundary == "file":
        files["large.md"] = "a" * (mcp.TP4_MAX_FILE_CODE_BYTES + 1)
    elif boundary == "total":
        files.update({f"large-{index}.md": "a" * mcp.TP4_MAX_FILE_CODE_BYTES
                      for index in range(5)})
    elif boundary == "artifacts":
        files.update({f"prose-{index}.md": "Generated inert prose.\n" for index in range(65)})
    else:
        monkeypatch.setattr(mcp, "transitive_remaining_seconds", lambda state: 0.0)
    result = mcp.node(state_for(files))
    reason = {"file": "size_limit", "total": "total_bytes_limit",
              "artifacts": "artifact_count_limit", "runtime": "runtime_limit"}[boundary]
    assert result["analyzer_status_events"][0]["status"] == "degraded"
    assert any(event.get("reason_code") == reason for event in result["inspection_ledger"])
    assert len(transport["requests"]) <= 64
    assert len(transport["prefixes"]) <= 128
    assert sum(size for _, size in transport["prefixes"]) <= mcp.TP4_MAX_TOTAL_CODE_BYTES


def test_last_permitted_finding_survives_later_prose(transport):
    files = executable_files()
    files["fixture-063.py"] = "print('GENERATED_FINDING')\n"
    files["prose.md"] = "Generated inert prose.\n"
    result = mcp.node(state_for(files))
    assert result["analyzer_status_events"][0]["status"] == "completed"
    assert len(result["findings"]) == 1
    assert result["findings"][0].evidence["code_path"] == "fixture-063.py"
    assert len(transport["requests"]) == 64


def test_provider_error_is_not_completed(transport):
    transport["error"] = True
    result = mcp.node(state_for(executable_files(1)))
    assert len(transport["requests"]) == 1
    assert result["analyzer_status_events"][0]["status"] == "failed"
    assert any(event["outcome"] == "failed" for event in result["inspection_ledger"])
