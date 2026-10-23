"""Wire-contract tests against the patched, installed NVIDIA SkillSpector."""

import asyncio
import json
import threading
import time

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from pydantic import BaseModel
from skillspector.providers.chat_models import UnsupportedControlError
from skillspector.providers.openai import OpenAIProvider


@pytest.fixture(autouse=True)
def controls(monkeypatch):
    for name in (
        "SKILLSPECTOR_TEMPERATURE",
        "SKILLSPECTOR_SEED",
        "SKILLSPECTOR_SERVICE_TIER",
        "SKILLSPECTOR_REASONING_EFFORT",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-credential")
    monkeypatch.setenv("SKILLSPECTOR_PROVIDER", "openai")
    monkeypatch.setenv("SKILLSPECTOR_REASONING_EFFORT", "medium")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")


def model(monkeypatch, handler, name="gpt-6.1-sol"):
    # Exercise LangChain's real OpenAI SDK, serializer, and response parser.
    llm = OpenAIProvider().create_chat_model(name, max_tokens=256)
    monkeypatch.setattr(
        llm.root_client._client, "send", lambda request, **kw: handler(request)
    )
    return llm


def response(output, status="completed"):
    return {
        "id": "resp_fixture",
        "object": "response",
        "created_at": 1,
        "status": status,
        "model": "gpt-6.1-sol",
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {"input_tokens": 12, "output_tokens": 7, "total_tokens": 19},
    }


def test_sol_tool_call_uses_responses_and_medium(monkeypatch):
    captured = []

    def handler(request):
        captured.append((request.url.path, json.loads(request.content)))
        return httpx.Response(
            200,
            request=request,
            json=response(
                [
                    {
                        "type": "function_call",
                        "id": "fc_1",
                        "call_id": "call_1",
                        "name": "read_file",
                        "arguments": '{"path":"SKILL.md"}',
                        "status": "completed",
                    }
                ]
            ),
        )

    llm = model(monkeypatch, handler).bind_tools(
        [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                    },
                },
            }
        ]
    )
    result = llm.invoke([HumanMessage("Inspect SKILL.md")])
    path, body = captured[0]
    assert path == "/v1/responses"
    assert body["reasoning"] == {"effort": "medium"}
    assert body["model"] == "gpt-6.1-sol"
    assert body["tools"][0]["type"] == "function"
    assert "temperature" not in body and "seed" not in body
    assert body["service_tier"] == "default"
    assert result.tool_calls[0]["id"] == "call_1"
    assert result.tool_calls[0]["args"] == {"path": "SKILL.md"}
    assert result.usage_metadata["total_tokens"] == 19
    assert result.response_metadata["model_name"] == "gpt-6.1-sol"


def test_sol_tool_history_roundtrip(monkeypatch):
    def handler(request):
        body = json.loads(request.content)
        assert any(
            item.get("type") == "function_call_output" and item["call_id"] == "call_1"
            for item in body["input"]
        )
        return httpx.Response(
            200,
            request=request,
            json=response(
                [
                    {
                        "type": "message",
                        "id": "msg_1",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {"type": "output_text", "text": "clean", "annotations": []}
                        ],
                    }
                ]
            ),
        )

    llm = model(monkeypatch, handler)
    result = llm.invoke(
        [
            HumanMessage("Inspect"),
            AIMessage(
                content="",
                tool_calls=[{"name": "read_file", "args": {}, "id": "call_1"}],
            ),
            ToolMessage(content="safe content", tool_call_id="call_1"),
        ]
    )
    assert result.content[0]["text"] == "clean"


def test_sol_structured_output_uses_responses(monkeypatch):
    class Verdict(BaseModel):
        clean: bool

    def handler(request):
        body = json.loads(request.content)
        assert request.url.path.endswith("/responses")
        assert body["text"]["format"]["type"] == "json_schema"
        return httpx.Response(
            200,
            request=request,
            json=response(
                [
                    {
                        "type": "message",
                        "id": "msg_2",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"clean":true}',
                                "annotations": [],
                            }
                        ],
                    }
                ]
            ),
        )

    assert (
        model(monkeypatch, handler)
        .with_structured_output(Verdict)
        .invoke("Inspect")
        .clean
    )


def test_other_model_retains_chat_route_and_base_override(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")

    def handler(request):
        assert str(request.url) == "https://provider.example/v1/chat/completions"
        body = json.loads(request.content)
        assert body["reasoning_effort"] == "medium"
        return httpx.Response(
            200,
            request=request,
            json={
                "id": "chat_fixture",
                "object": "chat.completion",
                "created": 1,
                "model": "other-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ok"},
                    }
                ],
            },
        )

    assert model(monkeypatch, handler, "other-model").invoke("Inspect").content == "ok"


@pytest.mark.parametrize(
    "name,value",
    [
        ("SKILLSPECTOR_SEED", "1"),
        ("SKILLSPECTOR_TEMPERATURE", "1"),
        ("SKILLSPECTOR_REASONING_EFFORT", "none"),
    ],
)
def test_unsupported_sol_controls_fail_before_network(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(UnsupportedControlError):
        OpenAIProvider().create_chat_model("gpt-6.1-sol", max_tokens=128)


@pytest.mark.parametrize("observed_model", ["gpt-6.1-sol", "gpt-6.1-sol-fixture"])
def test_sol_raw_report_retains_requested_and_observed_model(
    monkeypatch, observed_model
):
    from skillspector.llm_provenance import LLM_ANALYZER_SLOTS, capture_llm_provenance
    from skillspector.llm_utils import new_inference_usage_collector
    from skillspector.nodes.report import report

    def handler(request):
        payload = response(
            [
                {
                    "type": "message",
                    "id": "msg_raw",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {"type": "output_text", "text": "ok", "annotations": []}
                    ],
                }
            ]
        )
        payload["model"] = observed_model
        return httpx.Response(200, request=request, json=payload)

    llm = model(monkeypatch, handler)
    collector = new_inference_usage_collector(
        node="semantic_developer_intent",
        request_kind="chat_completion",
        model="gpt-6.1-sol",
        chat_model=llm,
    )
    llm.invoke("Inspect", config={"callbacks": [collector]})
    captured = capture_llm_provenance(dict.fromkeys(LLM_ANALYZER_SLOTS, "gpt-6.1-sol"))
    state = {
        "filtered_findings": [],
        "component_metadata": [],
        "has_executable_scripts": False,
        "manifest": {},
        "output_format": "json",
        "use_llm": True,
        "llm_call_log": [],
        "inference_usage": collector.snapshot(),
        "llm_provenance": captured,
    }
    raw = json.loads(report(state)["report_body"])
    provenance = raw["metadata"]["llm_provenance"]
    assert provenance["sampling"]["reasoning_effort"]["requested"] == "medium"
    assert provenance["sampling"]["reasoning_effort"]["forwarded_to_client"] == "medium"
    assert raw["metadata"]["inference_usage"][0]["model"] == observed_model
    # Upstream conservatively labels matching requested/observed IDs as requested.
    assert raw["metadata"]["inference_usage"][0]["model_source"] == (
        "requested_model" if observed_model == "gpt-6.1-sol" else "provider_response"
    )
    assert all(item["model"] == "gpt-6.1-sol" for item in provenance["analyzers"])


@pytest.mark.parametrize(
    "tier,expected",
    [
        ("", "default"),
        ("  ", "default"),
        ("default", "default"),
        (" flex ", "flex"),
        ("priority", "priority"),
        ("auto", "auto"),
    ],
)
def test_sol_service_tier_wire_override(monkeypatch, tier, expected):
    monkeypatch.setenv("SKILLSPECTOR_SERVICE_TIER", tier)

    def handler(request):
        assert json.loads(request.content)["service_tier"] == expected
        return httpx.Response(200, request=request, json=response([]))

    model(monkeypatch, handler).invoke("Inspect")


@pytest.mark.parametrize("tier", ["unsupported", "secret-tier-fixture"])
def test_sol_invalid_service_tier_fails_before_network(monkeypatch, tier):
    monkeypatch.setenv("SKILLSPECTOR_SERVICE_TIER", tier)
    with pytest.raises(
        UnsupportedControlError, match="Unsupported SKILLSPECTOR_SERVICE_TIER"
    ):
        OpenAIProvider().create_chat_model("gpt-6.1-sol", max_tokens=128)


def test_other_model_ignores_sol_service_tier(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_SERVICE_TIER", "unsupported")
    llm = OpenAIProvider().create_chat_model("gpt-5.5", max_tokens=128)
    assert llm.service_tier is None


@pytest.fixture
def batch_transport(monkeypatch):
    observed = {"active": 0, "peak": 0, "paths": [], "error_paths": set()}
    lock = threading.Lock()

    def begin(request):
        body = json.loads(request.content)
        assert request.url.path == "/v1/responses"
        assert body["model"] == "gpt-6.1-sol"
        assert body["reasoning"] == {"effort": "medium"}
        assert body["service_tier"] == "default"
        prompt = body["input"][0]["content"]
        if isinstance(prompt, list):
            prompt = prompt[0]["text"]
        path = prompt.split("## File: ", 1)[1].split("\n", 1)[0]
        with lock:
            observed["active"] += 1
            observed["peak"] = max(observed["peak"], observed["active"])
            observed["paths"].append(path)
        return path

    def finish(request, path):
        with lock:
            observed["active"] -= 1
        if "after_response" in observed:
            observed["after_response"]()
        if path in observed["error_paths"]:
            return httpx.Response(
                400,
                request=request,
                json={"error": {"type": "invalid_request_error", "message": "Inert failure"}},
            )
        finding = {
            "rule_id": "SSD-1",
            "message": "Synthetic retained finding",
            "severity": "HIGH",
            "start_line": 1,
            "confidence": 0.99,
            "explanation": "Inert fixture evidence",
            "remediation": "Inert fixture mitigation",
        }
        payload = {"findings": [finding] if path.endswith("19.md") else []}
        return httpx.Response(
            200,
            request=request,
            json=response([
                {
                    "type": "message",
                    "id": "msg_batch",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{
                        "type": "output_text",
                        "text": json.dumps(payload),
                        "annotations": [],
                    }],
                }
            ]),
        )

    def send(client, request, **kwargs):
        path = begin(request)
        time.sleep(0.05)
        return finish(request, path)

    async def asend(client, request, **kwargs):
        path = begin(request)
        await asyncio.sleep(0.05)
        return finish(request, path)

    probe = OpenAIProvider().create_chat_model("gpt-6.1-sol", max_tokens=256)
    monkeypatch.setattr(type(probe.root_client._client), "send", send)
    monkeypatch.setattr(type(probe.root_async_client._client), "send", asend)
    return observed


def discovery_state(seconds):
    from skillspector.state import WorkflowResourceBudget

    files = {f"fixture-{index:02}.md": "Inert generated text." for index in range(20)}
    budget = WorkflowResourceBudget(max_seconds=seconds)
    budget.start()
    return {
        "use_llm": True,
        "components": list(files),
        "file_cache": files,
        "model_config": {"default": "gpt-6.1-sol"},
        "workflow_resource_budget": budget,
    }


def test_security_discovery_finishes_all_batches_with_shared_budget(
    monkeypatch, batch_transport
):
    from skillspector.nodes.analyzers.semantic_security_discovery import node

    monkeypatch.setenv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "5")
    state = discovery_state(5)
    result = node(state)
    assert result["analyzer_status_events"][0]["status"] == "completed"
    assert sorted(batch_transport["paths"]) == sorted(state["components"])
    assert 1 < batch_transport["peak"] <= 5
    assert batch_transport["active"] == 0
    assert len(result["inspection_ledger"]) == 20
    assert result["llm_call_log"][0]["ok"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0].file == "fixture-19.md"
    assert result["findings"][0].message == "Synthetic retained finding"
    assert len(result["inference_usage"]) == 20


@pytest.mark.parametrize("concurrency", [1, 3])
def test_security_discovery_respects_configured_pool(monkeypatch, batch_transport, concurrency):
    from skillspector.nodes.analyzers.semantic_security_discovery import node

    monkeypatch.setenv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", str(concurrency))
    result = node(discovery_state(5))
    assert result["analyzer_status_events"][0]["status"] == "completed"
    assert batch_transport["peak"] <= concurrency
    assert len(batch_transport["paths"]) == 20


def test_security_discovery_shares_pool_with_sibling_analyzers(monkeypatch, batch_transport):
    from concurrent.futures import ThreadPoolExecutor

    from skillspector.nodes.analyzers.semantic_developer_intent import node as intent
    from skillspector.nodes.analyzers.semantic_quality_policy import node as quality
    from skillspector.nodes.analyzers.semantic_security_discovery import node as security

    monkeypatch.setenv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "5")
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(node, discovery_state(5)) for node in (security, intent, quality)]
        results = [future.result(timeout=10) for future in futures]
    assert 1 < batch_transport["peak"] <= 5
    assert batch_transport["active"] == 0
    assert len(batch_transport["paths"]) == 60
    for result in results:
        assert result["analyzer_status_events"][0]["status"] == "completed"
        assert len(result["inspection_ledger"]) == 20
        assert len(result["findings"]) == 1


def test_security_discovery_keeps_failed_batch_and_successful_findings(monkeypatch, batch_transport):
    from skillspector.nodes.analyzers.semantic_security_discovery import node

    monkeypatch.setenv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "5")
    batch_transport["error_paths"].add("fixture-00.md")
    result = node(discovery_state(5))
    assert result["analyzer_status_events"][0]["status"] != "completed"
    assert result["llm_call_log"][0]["ok"] is False
    assert len(result["inspection_ledger"]) == 20
    assert any(
        event["path"] == "fixture-00.md" and event["outcome"] == "failed"
        for event in result["inspection_ledger"]
    )
    assert sorted(batch_transport["paths"]) == sorted(discovery_state(5)["components"])
    assert result["findings"][0].file == "fixture-19.md"


def test_security_discovery_deadline_accounts_for_unstarted_batches(monkeypatch, batch_transport):
    from skillspector.nodes.analyzers.semantic_security_discovery import node

    monkeypatch.setenv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "1")
    clock = {"now": 100.0}
    monkeypatch.setattr("skillspector.state.monotonic", lambda: clock["now"])
    batch_transport["after_response"] = lambda: clock.update(now=101.0)
    state = discovery_state(0.15)
    result = node(state)
    assert result["analyzer_status_events"][0]["status"] != "completed"
    assert result["llm_call_log"][0]["ok"] is False
    assert len(result["inspection_ledger"]) == 20
    assert sorted(event["path"] for event in result["inspection_ledger"]) == sorted(state["components"])
    assert 0 < len(batch_transport["paths"]) < 20
    assert batch_transport["active"] == 0
