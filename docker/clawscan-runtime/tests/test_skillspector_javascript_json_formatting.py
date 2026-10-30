"""Native JSON formatting must preserve value-use inspection obligations."""

import pytest

from skillspector.inspection_ledger import LedgerOutcome
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner


def ledger(source):
    return static_runner.run_static_patterns_with_ledger(
        {"components": ["inspect.mjs"], "file_cache": {"inspect.mjs": source}},
        [tool],
    )


def test_null_replacer_and_numeric_spacing_preserve_native_output_inspection():
    result = ledger("process.stdout.write(JSON.stringify(`status ${value}`, null, 2));")

    assert result["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize("suffix", ["", ", null", ", null, 0", ", null, 2.5", ", null, 0x2"])
def test_only_inert_optional_arguments_extend_the_existing_native_contract(suffix):
    source = f"process.stdout.write(JSON.stringify(`status ${{value}}`{suffix}));"

    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize(
    "source",
    [
        "const encode=JSON.stringify; process.stdout.write(encode(`status ${value}`,null,2));",
        "const record={text:JSON.stringify(`status ${value}`,null,2)};"
        "process.stdout.write(JSON.stringify(record));",
        "function message(){return JSON.stringify(`status ${value}`,null,2);}"
        "process.stdout.write(message());",
        "const value='ready';const record={text:`status ${value}`};"
        "process.stdout.write(JSON.stringify(record,null,2));",
    ],
)
def test_formatted_strings_keep_their_existing_alias_record_and_output_uses(source):
    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_plain_record_formatting_uses_closed_native_stream_output(stream):
    source = (
        "const record={text:`ready ${1}`};"
        f"process.{stream}.write(JSON.stringify(record,null,2));"
    )

    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize(
    "source",
    [
        "process.stdout.write(JSON.stringify(`status ${value}`,replacer,2));",
        "process.stdout.write(JSON.stringify(`status ${value}`,(key,value)=>{"
        "obj.run(value);return value;},2));",
        "process.stdout.write(JSON.stringify(`status ${value}`,[],2));",
        "process.stdout.write(JSON.stringify(`status ${value}`,null,spacing));",
        "process.stdout.write(JSON.stringify(`status ${value}`,null,{valueOf:consume}));",
        "process.stdout.write(JSON.stringify(`status ${value}`,null,2,extra));",
        "process.stdout.write(JSON.stringify(...[`status ${value}`],null,2));",
        "process.stdout.write(JSON.stringify(`status ${value}`,...[null,2]));",
        "process.stdout.write(JSON.parse(`\"${value}\"`,null));",
        "function encode(JSON){return JSON.stringify(`status ${value}`,null,2);}",
        "JSON.stringify=consume; process.stdout.write(JSON.stringify(`status ${value}`,null,2));",
        "const encode=JSON.stringify; use(encode);"
        "process.stdout.write(encode(`status ${value}`,null,2));",
        r"JSON['string\u0069fy']=consume;"
        "process.stdout.write(JSON.stringify(`status ${value}`,null,2));",
        "const text=JSON.stringify(`${command}${flags} /`,null,2);"
        "process.stdout.write(text);obj.run(text);",
        "const payload={toJSON:consume,command:`tou${'ch'} /tmp/marker`};"
        "process.stdout.write(JSON.stringify(payload,null,2));",
        "const payload={command:`tou${'ch'} /tmp/marker`};payload.toJSON=consume;"
        "process.stdout.write(JSON.stringify(payload,null,2));",
        "const payload={get value(){return obj.run(`tou${'ch'} /tmp/marker`);}};"
        "process.stdout.write(JSON.stringify(payload,null,2));",
        "const payload={text:`ready ${1}`};"
        "process.stdout.write(JSON.stringify(payload,null,2),callback);",
        "const payload={text:`ready ${1}`};process.stdout.write=consume;"
        "process.stdout.write(JSON.stringify(payload,null,2));",
        "const payload={text:`ready ${1}`};use(process.stdout);"
        "process.stdout.write(JSON.stringify(payload,null,2));",
    ],
)
def test_formatting_never_discharges_unknown_or_executable_value_uses(source):
    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.PARTIAL


def test_formatting_preserves_raw_destructive_findings():
    result = ledger("process.stdout.write(JSON.stringify(`rm -rf / ${value}`,null,2));")

    assert any(finding.rule_id == "TM1" and finding.severity == "HIGH" for finding in result["findings"])
