"""Wire-contract tests against the patched, installed NVIDIA SkillSpector."""

import json

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
        "SKILLSPECTOR_REASONING_EFFORT",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-credential")
    monkeypatch.setenv("SKILLSPECTOR_PROVIDER", "openai")
    monkeypatch.setenv("SKILLSPECTOR_REASONING_EFFORT", "medium")


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
    assert "service_tier" not in body
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
