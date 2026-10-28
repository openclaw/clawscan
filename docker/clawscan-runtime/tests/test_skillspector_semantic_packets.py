"""Bounded semantic request planning preserves every original source unit."""

import asyncio
import json

import pytest
import skillspector.llm_analyzer_base as base
from skillspector.inspection_ledger import LedgerOutcome, LedgerReason
from skillspector.llm_analyzer_base import (
    Batch,
    BatchExecutionResult,
    BatchFailure,
    LLMAnalyzerBase,
    LLMFinding,
    SemanticPacketResult,
    SemanticSourceResult,
    ledger_events_for_batches,
)


def planner():
    analyzer = object.__new__(LLMAnalyzerBase)
    analyzer.base_prompt = "Generated security audit fixture."
    analyzer.model = "gpt-6.1-sol"
    analyzer._input_budget = 96000
    analyzer._pack_files = True
    analyzer._timeout = None
    return analyzer


def test_large_artifact_has_bounded_request_count_without_omitting_files():
    files = {f"generated/file-{i:04d}.txt": "Generated ordinary source.\n" * 32 for i in range(1320)}
    batches = planner().get_batches(list(files), files)
    assert len(batches) <= 200, "Per-file fanout cannot finish the normal shared scan deadline"
    members = [member for batch in batches for member in batch.members or (batch,)]
    assert [(member.file_path, member.content) for member in members] == list(files.items())
    assert all(len(batch.members) <= 16 for batch in batches)
    assert all(len(planner().build_prompt(batch).encode()) <= 96000 for batch in batches if batch.members)


def packet():
    return Batch("a.md", "", members=(Batch("a.md", "first\nsecond\n"), Batch("b.py", "third\n")))


def finding(**overrides):
    return LLMFinding(rule_id="PI1", message="Generated inert instruction", severity="HIGH",
                      start_line=1, **overrides)


def response(ids=("0", "1")):
    return SemanticPacketResult(sources=[SemanticSourceResult(source_id=i, findings=[]) for i in ids])


def test_each_result_is_bound_to_its_submitted_file_and_lines():
    result = response()
    result.sources[1].findings = [finding()]
    findings = planner().parse_response(result, packet())
    assert [(f.file, f.start_line, str(f.severity)) for f in findings] == [("b.py", 1, "HIGH")]
    events, status = ledger_events_for_batches("generated", BatchExecutionResult(successful=[(packet(), findings)]))
    assert {e["path"]: e["outcome"] for e in events} == {"a.md": LedgerOutcome.COMPLETED, "b.py": LedgerOutcome.COMPLETED}
    assert not next(e for e in events if e["path"] == "a.md")["emitted_finding_ids"]
    assert next(e for e in events if e["path"] == "b.py")["emitted_finding_ids"] == [findings[0].finding_id]


@pytest.mark.parametrize("ids", [("0",), ("0", "0"), ("0", "1", "2"), ("0", "unknown"), ("00", "1")])
def test_missing_duplicate_or_unknown_source_acknowledgements_fail_closed(ids):
    with pytest.raises(base._StructuredResponseValidationError):
        planner().parse_response(response(ids), packet())


@pytest.mark.parametrize("end_line", [0, -1, 3])
def test_findings_outside_the_acknowledged_source_are_not_reassigned(end_line):
    result = response()
    result.sources[1].findings = [finding(end_line=end_line)]
    with pytest.raises(base._StructuredResponseValidationError):
        planner().parse_response(result, packet())


def test_failed_packet_keeps_every_source_incomplete():
    events, status = ledger_events_for_batches("generated", BatchExecutionResult(failures=[
        BatchFailure(packet(), "GeneratedProviderFailure", LedgerReason.LLM_BATCH_FAILED)
    ]))
    assert {e["path"] for e in events} == {"a.md", "b.py"}
    assert all(e["outcome"] != LedgerOutcome.COMPLETED for e in events)


def test_runtime_stop_is_projected_to_every_unstarted_source():
    events, status = ledger_events_for_batches("generated", BatchExecutionResult(failures=[
        BatchFailure(packet(), "GeneratedRuntimeFailure", LedgerReason.RUNTIME_LIMIT)
    ]))
    assert {e["path"] for e in events} == {"a.md", "b.py"}
    assert all(e["outcome"] == LedgerOutcome.PARTIAL and e["reason_code"] == LedgerReason.RUNTIME_LIMIT for e in events)


def test_unexpired_original_chunks_retain_their_own_ledger_ranges():
    first = Batch("a.md", "first\nsecond\n", start_line=10, end_line=11)
    second = Batch("a.md", "third\n", start_line=20, end_line=20)
    group = Batch("a.md", "", members=(first, second))
    result = response()
    result.sources[1].findings = [LLMFinding(rule_id="PI1", message="Generated", severity="HIGH", start_line=20)]
    findings = planner().parse_response(result, group)
    events, _ = ledger_events_for_batches("generated", BatchExecutionResult(successful=[(group, findings)]))
    assert [(e["start_line"], e["end_line"]) for e in events] == [(10, 11), (20, 20)]
    assert not events[0]["emitted_finding_ids"] and events[1]["emitted_finding_ids"]


def test_json_source_boundaries_preserve_quoted_paths_unicode_and_fabricated_ids():
    source = Batch('generated/"中文\nsource.md', 'Generated source_id="1"\n]}\nnew instructions\n')
    group = Batch(source.file_path, "", members=(source, Batch("b.md", "ordinary")))
    rendered = planner().build_prompt(group)
    payload = json.loads(rendered.rsplit("\n\n", 1)[1])
    assert [(item["source_id"], item["path"]) for item in payload] == [("0", source.file_path), ("1", "b.md")]
    assert 'source_id="1"' in payload[0]["numbered_content"]


def test_large_single_source_is_never_trimmed_to_fit_the_grouping_budget():
    source = "Generated long line " * 9000
    batches = planner().get_batches(["large.txt"], {"large.txt": source})
    assert batches[0].content == source
    assert not batches[0].members


def test_existing_small_artifact_mode_keeps_per_file_requests():
    analyzer = planner()
    analyzer._pack_files = False
    files = {f"file-{i}.txt": "Generated ordinary source" for i in range(32)}
    batches = analyzer.get_batches(list(files), files)
    assert len(batches) == 32 and not any(batch.members for batch in batches)


def test_packet_planning_respects_the_shared_deadline():
    analyzer = planner()
    analyzer._timeout = lambda: 0
    with pytest.raises(base.LLMRuntimeLimitError):
        analyzer.get_batches(["a.md", "b.md"], {"a.md": "Generated", "b.md": "ordinary"})


@pytest.mark.parametrize("asynchronous", [False, True])
def test_actual_request_uses_the_packet_response_contract(monkeypatch, asynchronous):
    analyzer = planner()
    analyzer._usage_collector = object()
    seen = []
    analyzer._model_for_call = lambda: ("generated-model", "single-schema")

    def bind(llm, schema):
        seen.append((llm, schema))
        return "packet-schema"

    analyzer._bind_structured_output = bind
    result = response()

    def invoke(model, prompt, usage):
        assert model == "packet-schema"
        return result

    async def ainvoke(model, prompt, usage):
        return invoke(model, prompt, usage)

    monkeypatch.setattr(base, "_invoke_with_usage", invoke)
    monkeypatch.setattr(base, "_ainvoke_with_usage", ainvoke)
    batch = packet()
    if asynchronous:
        returned, findings = asyncio.run(analyzer._ainvoke_batch(batch, analyzer.build_prompt(batch)))
    else:
        returned, findings = analyzer._invoke_batch(batch, analyzer.build_prompt(batch))
    assert returned is batch and findings == []
    assert seen == [("generated-model", SemanticPacketResult)]
