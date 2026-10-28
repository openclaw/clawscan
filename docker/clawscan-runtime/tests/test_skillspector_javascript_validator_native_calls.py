"""Native result typing requires the complete consumed argument contract."""

import pytest

from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner


@pytest.mark.parametrize("bounds", ["offset", "0,offset", "offset,offset"])
def test_argv_slice_does_not_invoke_unproved_bound_conversion(bounds):
    source = (
        'const offset={valueOf:consume};'
        f'console.log(`x${{process.argv.slice({bounds}).join(",")}}`);'
    )
    report = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.mjs"], "file_cache": {"case.mjs": source}}, [tool]
    )
    assert report["inspection_ledger"][0]["outcome"] != "completed"
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()


@pytest.mark.parametrize("receiver", ["process.argv", "args"])
def test_unknown_bound_cannot_invalidate_a_later_console_identity(receiver):
    source = ('const args=process.argv;' if receiver == "args" else "") + (
        'const offset={valueOf:consume};'
        f'{receiver}.slice(offset);console.log(`tou${{"ch"}} /tmp/marker`);'
    )
    report = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.mjs"], "file_cache": {"case.mjs": source}}, [tool]
    )
    assert report["inspection_ledger"][0]["outcome"] != "completed"
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()


@pytest.mark.parametrize("bounds", ["", "2", "1,3", '"1",null'])
def test_argv_slice_scalar_bounds_preserve_native_result_identity(bounds):
    source = f'console.log(`x${{process.argv.slice({bounds}).join(",")}}`);'
    report = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.mjs"], "file_cache": {"case.mjs": source}}, [tool]
    )
    assert report["inspection_ledger"][0]["outcome"] == "completed"
