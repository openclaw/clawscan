"""Offline finding-identity contracts through the installed SDK's real graph."""

import importlib
import json
from dataclasses import replace

import pytest
from skillspector.inspection_ledger import (
    LedgerOutcome,
    LedgerReason,
    LedgerRecordType,
    analyzer_status_for_events,
    ledger_event,
)
from skillspector.models import OCCURRENCE_FINDING_ID_KEY, AnalyzerFinding, Location, Severity
from skillspector.nodes.analyzers.static_runner import analyzer_finding_to_finding
from skillspector.suppression import Baseline, SuppressionRule


def findings():
    original = AnalyzerFinding(
        rule_id="PI1", message="Generated inert match", severity=Severity.HIGH,
        location=Location(file="generated.md", start_line=1), confidence=0.9,
        matched_text="INERT_MARKER", context="INERT_MARKER",
    )
    first = replace(analyzer_finding_to_finding(original), finding_id="generated-a")
    second = replace(analyzer_finding_to_finding(original), finding_id="generated-b")
    return first, second


def run_graph(monkeypatch, produced, *, extra_events=(), **state):
    workflow = importlib.import_module("skillspector.graph")
    event = ledger_event(
        outcome=LedgerOutcome.COMPLETED, phase="behavioral", analyzer_id="behavioral_ast",
        path="generated.md", emitted_finding_ids=[finding.finding_id for finding in produced],
    )

    def producer(current):
        return {
            "findings": produced, "inspection_ledger": [event, *extra_events],
            "analyzer_status_events": [analyzer_status_for_events("behavioral_ast", [event])],
        }

    monkeypatch.setattr(workflow, "resolve_input", lambda current: {})
    monkeypatch.setattr(workflow, "build_context", lambda current: {})
    monkeypatch.setattr(workflow, "ANALYZER_NODE_IDS", ["behavioral_ast"])
    monkeypatch.setattr(workflow, "ANALYZER_MODULES", {})
    monkeypatch.setattr(workflow, "ANALYZER_NODES", {"behavioral_ast": producer})
    return workflow.create_graph().invoke({
        "components": ["generated.md"],
        "component_metadata": [{"path": "generated.md", "type": "markdown"}],
        "file_cache": {"generated.md": "INERT_MARKER INERT_MARKER\nINERT_MARKER\n"},
        "manifest": {"name": "generated", "description": "Generated inert documentation"},
        "skill_path": "generated-fixture", "use_llm": False,
        "output_format": "json", "findings": [], **state,
    })


@pytest.mark.parametrize("difference", [
    "none", "line", "columns", "evidence", "classification", "snippet", "source",
])
def test_distinct_canonical_ids_survive_report_compaction(monkeypatch, difference):
    first, second = findings()
    if difference == "line":
        second = replace(second, start_line=2)
    elif difference == "columns":
        first = replace(first, start_column=0, end_column=12)
        second = replace(second, start_column=13, end_column=25)
    elif difference == "evidence":
        second = replace(second, evidence={"generated": "different"})
    elif difference == "classification":
        second = replace(second, severity="CRITICAL")
    elif difference == "snippet":
        second = replace(second, code_snippet="INERT_MARKER second generated context")
    elif difference == "source":
        second = replace(second, source_identity="generated/source", source_digest="sha256:inert")
    result = run_graph(monkeypatch, [first, second])
    report = json.loads(result["report_body"])
    expected = {finding.finding_id: finding for finding in [first, second]}
    assert result["analysis_completeness"]["findings_before_filtering"] == 2
    assert result["analysis_completeness"]["findings_after_filtering"] == 2
    assert result["analysis_completeness"]["is_complete"] is True
    assert set(result["effective_finding_ids"]) == set(expected)
    assert {finding.finding_id for finding in result["active_findings"]} == set(expected)
    assert len(report["issues"]) == 2
    for issue in report["issues"]:
        original = expected.pop(issue["finding_id"])
        assert issue["severity"] == original.severity
        assert issue["code_snippet"] == original.code_snippet
        assert issue["evidence"] == original.evidence
        assert issue["location"] == original.to_dict()["location"]
    assert not expected
    assert report["suppressed"] == []
    assert {item["properties"]["findingId"]
            for item in result["sarif_report"]["runs"][0]["results"]} == {
                first.finding_id, second.finding_id}


def test_repeated_id_is_an_update_not_an_extra_finding(monkeypatch):
    first, second = findings()
    result = run_graph(monkeypatch, [first, replace(second, finding_id=first.finding_id)])
    report = json.loads(result["report_body"])
    assert report["analysis_completeness"]["findings_before_filtering"] == 1
    assert report["analysis_completeness"]["findings_after_filtering"] == 1
    assert [issue["finding_id"] for issue in report["issues"]] == [first.finding_id]


def test_suppression_is_explicit_and_retains_both_ids(monkeypatch):
    result = run_graph(monkeypatch, list(findings()), baseline=Baseline(
        rules=[SuppressionRule(rule_id="PI1", reason="Generated explicit suppression")]))
    report = json.loads(result["report_body"])
    assert report["issues"] == []
    assert report["suppressed_count"] == 2
    assert {issue["finding_id"] for issue in report["suppressed"]} == {"generated-a", "generated-b"}
    assert report["analysis_completeness"]["findings_after_filtering"] == 2


def test_multiple_locations_are_occurrences_not_extra_canonical_findings(monkeypatch):
    first, _ = findings()
    first = replace(first, occurrences=[
        {"file": "generated.md", "start_line": 1, "end_line": None},
        {"file": "generated.md", "start_line": 2, "end_line": None},
    ])
    result = run_graph(monkeypatch, [first])
    report = json.loads(result["report_body"])
    assert report["analysis_completeness"]["findings_after_filtering"] == 1
    assert [issue["finding_id"] for issue in report["issues"]] == [first.finding_id] * 2


def test_repeated_same_id_location_does_not_invent_an_occurrence(monkeypatch):
    first, _ = findings()
    occurrence = {"file": "generated.md", "start_line": 1, "end_line": None}
    first = replace(first, occurrences=[occurrence, dict(occurrence)])
    result = run_graph(monkeypatch, [first])
    report = json.loads(result["report_body"])
    assert report["analysis_completeness"]["findings_after_filtering"] == 1
    assert [issue["finding_id"] for issue in report["issues"]] == [first.finding_id]


@pytest.mark.parametrize("invalid_identity", [None, "", [], {}])
def test_invalid_private_occurrence_identity_uses_canonical_id(monkeypatch, invalid_identity):
    produced = [replace(finding, occurrences=[{
        "file": finding.file, "start_line": finding.start_line,
        OCCURRENCE_FINDING_ID_KEY: invalid_identity,
    }]) for finding in findings()]
    result = run_graph(monkeypatch, produced)
    report = json.loads(result["report_body"])
    assert {issue["finding_id"] for issue in report["issues"]} == {"generated-a", "generated-b"}
    assert report["analysis_completeness"]["findings_after_filtering"] == 2


def test_actual_output_limit_is_still_incomplete(monkeypatch):
    finalizer = importlib.import_module("skillspector.nodes.finalize_inspection_ledger")
    reporter = importlib.import_module("skillspector.nodes.report")
    monkeypatch.setattr(finalizer, "MAX_FINDING_OUTPUT_RECORDS", 1)
    monkeypatch.setattr(reporter, "MAX_FINDING_OUTPUT_RECORDS", 1)
    result = run_graph(monkeypatch, list(findings()))
    report = json.loads(result["report_body"])
    assert len(result["findings"]) == 2
    assert len(report["issues"]) == 1
    assert report["analysis_completeness"]["is_complete"] is False
    assert any(row["reason_code"] == "output_limit"
               for row in report["analysis_completeness"]["ledger_exceptions"])


@pytest.mark.parametrize("reason", [LedgerReason.REFERENCE_MISSING, LedgerReason.STATIC_PARSE_LIMIT])
def test_reference_notifications_and_real_limits_are_retained(monkeypatch, reason):
    event = ledger_event(
        outcome=LedgerOutcome.PARTIAL, record_type=LedgerRecordType.SYSTEM,
        phase="reference_resolution" if reason == LedgerReason.REFERENCE_MISSING else "static",
        path="generated.md", start_line=1, end_line=1, reason=reason,
    )
    result = run_graph(monkeypatch, list(findings()), extra_events=[event])
    report = json.loads(result["report_body"])
    assert len(report["issues"]) == 2
    assert report["analysis_completeness"]["is_complete"] is False
    assert any(row["reason_code"] == reason
               for row in report["analysis_completeness"]["ledger_exceptions"])


def test_unknown_semantic_telemetry_stays_incomplete_without_provider_calls(monkeypatch):
    result = run_graph(monkeypatch, list(findings()), llm_requested=True,
                       llm_preflight_error="Generated unavailable runtime")
    report = json.loads(result["report_body"])
    assert len(report["issues"]) == 2
    assert report["analysis_completeness"]["is_complete"] is False
    assert report["metadata"]["llm_requested"] is True
    assert report["metadata"]["llm_available"] is False
