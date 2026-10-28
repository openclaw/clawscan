# SPDX-License-Identifier: Apache-2.0
"""Large supported file/analyzer matrices retain terminal evidence under byte bounds."""

import json

import skillspector.state as state_module
from skillspector.inspection_ledger import (
    LedgerOutcome,
    LedgerReason,
    analyzer_status_for_events,
    finalize_ledger,
    inspection_work_id,
    ledger_event,
)


def _event(path: str, analyzer: str = "static_fixture", **kwargs):
    return ledger_event(
        outcome=LedgerOutcome.COMPLETED, phase="static", path=path, analyzer_id=analyzer, **kwargs
    )


def _size(events):
    return len(json.dumps(events, ensure_ascii=True, separators=(",", ":")))


def test_large_file_analyzer_matrix_retains_every_terminal_identity():
    paths = [f"employees/engineering/backend-developer/guide-{i}.md" for i in range(1339)]
    retained = []
    statuses = []
    expected = set()
    for i in range(22):
        analyzer = f"static_fixture_{i}"
        rows = [_event(path, analyzer) for path in paths]
        expected.update(row["work_id"] for row in rows)
        statuses.append(analyzer_status_for_events(analyzer, rows))
        retained = state_module.merge_inspection_ledger(retained, rows)
    assert {row["work_id"] for row in retained} == expected
    completeness, _ = finalize_ledger(
        {
            "components": paths,
            "findings": [],
            "inspection_ledger": retained,
            "analyzer_status_events": statuses,
        }
    )
    assert completeness["fully_inspected_files"] == len(paths)
    assert completeness["status"] == "complete"


def test_byte_overflow_stays_partial_and_counts_subsequent_producers(monkeypatch):
    monkeypatch.setattr(state_module, "MAX_INSPECTION_LEDGER_BYTES", 8192)
    rows = [_event("nested/" + "文" * 200 + f"-{i}.md") for i in range(30)]
    retained = state_module.merge_inspection_ledger([], rows[:20])
    assert _size(retained) <= 8192
    assert retained[-1]["reason_code"] == LedgerReason.OUTPUT_LIMIT
    assert retained[-1]["observed_records"] == 20
    prefix = retained[:-1]
    retained = state_module.merge_inspection_ledger(retained, rows[20:])
    assert retained[:-1] == prefix
    assert retained[-1]["observed_records"] == 30
    assert retained[-1]["observed_bytes"] >= _size(rows)
    assert retained[-1]["limit_bytes"] == 8192
    assert _size(retained) <= 8192
    completeness, _ = finalize_ledger(
        {
            "components": [r["path"] for r in rows],
            "findings": [],
            "inspection_ledger": retained,
            "analyzer_status_events": [],
        }
    )
    assert completeness["status"] != "complete"


def test_one_large_finding_list_cannot_bypass_byte_budget(monkeypatch):
    monkeypatch.setattr(state_module, "MAX_INSPECTION_LEDGER_BYTES", 8192)
    row = _event("SKILL.md", emitted_finding_ids=[f"finding-{i}" for i in range(2000)])
    retained = state_module.merge_inspection_ledger([], [row])
    assert len(retained) == 1
    assert retained[0]["reason_code"] == LedgerReason.OUTPUT_LIMIT
    assert _size(retained) <= 8192


def test_oversized_marker_path_keeps_valid_system_work_identity(monkeypatch):
    monkeypatch.setattr(state_module, "MAX_INSPECTION_LEDGER_BYTES", 1024)
    row = _event("nested/" + "文" * 2000 + ".md")
    retained = state_module.merge_inspection_ledger([], [row])
    assert len(retained) == 1
    marker = retained[0]
    assert marker["path"] == "SKILL.md"
    assert marker["work_id"] == inspection_work_id("system:ledger_output", "SKILL.md", None, None)
    assert _size(retained) <= 1024


def test_ascii_array_framing_cannot_exceed_byte_budget(monkeypatch):
    rows = [_event(f"guide-{i}.md") for i in range(12)]
    record_bytes = sum(state_module._ledger_event_bytes(row) for row in rows)
    assert record_bytes >= 1024
    monkeypatch.setattr(state_module, "MAX_INSPECTION_LEDGER_BYTES", record_bytes)
    retained = state_module.merge_inspection_ledger([], rows)
    assert _size(retained) <= record_bytes
    assert retained[-1]["reason_code"] == LedgerReason.OUTPUT_LIMIT
    assert retained[-1]["observed_bytes"] >= _size(rows)
