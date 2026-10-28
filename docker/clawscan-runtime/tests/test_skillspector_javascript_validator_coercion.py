"""Primitive results do not prove the effects of implicit operand conversion."""

import pytest

from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner

CASES = {
    "template_to_string": ('toString', '`${payload}`'),
    "number_value_of": ('valueOf', '`${Number(payload)}`'),
    "number_alias": ('valueOf', '`${convert(payload)}`'),
    "string_to_string": ('toString', '`${String(payload)}`'),
    "regexp_pattern": ('toString', '`${new RegExp(payload).test("x")}`'),
    "regexp_flags": ('toString', '`${new RegExp("x",payload).test("x")}`'),
    "json_record": ('toJSON', 'JSON.stringify(payload)'),
    "json_nested_record": ('toJSON', 'JSON.stringify({nested:payload})'),
    "json_array": ('toJSON', 'JSON.stringify([payload])'),
    "comparison": ('valueOf', '`${payload < 1}`'),
    "abstract_equality": ('valueOf', '`${payload == 1}`'),
    "addition": ('valueOf', '`${payload + 1}`'),
    "subtraction": ('valueOf', '`${payload - 1}`'),
    "unary_number": ('valueOf', '`${+payload}`'),
    "unary_complement": ('valueOf', '`${~payload}`'),
    "computed_key": ('toString', '`${({})[payload]}`'),
    "computed_record_key": ('toString', 'JSON.stringify({[payload]:1})'),
    "search_argument": ('toString', '`${"x".includes(payload)}`'),
    "join_element": ('toString', '`${[payload].join(",")}`'),
    "math_argument": ('valueOf', '`${Math.abs(payload)}`'),
}


def source_for(hook, expression):
    return (
        ('const convert=Number;' if 'convert(payload)' in expression else '')
        +         f'const payload={{{hook}:consume,command:`tou${{"ch"}} /tmp/marker`}};'
        'const errors=[];'
        f'errors.push({expression});console.log(JSON.stringify(errors));'
    )


@pytest.mark.parametrize("case", CASES, ids=CASES)
def test_implicit_callback_operand_remains_individually_incomplete(case):
    source = source_for(*CASES[case])
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.cjs"], "file_cache": {"case.cjs": source}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] != "completed"
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()


@pytest.mark.parametrize("mutation", [
    'payload.toJSON=consume;',
    'const alias=payload;alias.toJSON=consume;',
    'payload["toJSON"]=consume;',
])
def test_serialization_does_not_trust_mutated_fresh_records(mutation):
    source = (
        'const payload={command:`tou${"ch"} /tmp/marker`};' + mutation
        + 'const errors=[];errors.push(JSON.stringify(payload));console.log(JSON.stringify(errors));'
    )
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()


@pytest.mark.parametrize("expression", [
    '`${Number("1")}`',
    '`${String(1)}`',
    '`${1 < 2}`',
    '`${1 == "1"}`',
    '`${1 + 2}`',
    '`${+1}`',
    '`${Math.abs(-1)}`',
    'JSON.stringify({nested:[{value:`x${1}`}],ok:true})',
    '`${Boolean(payload)}`',
    '`${payload === payload}`',
    '`${!payload}`',
])
def test_proved_scalar_and_plain_serialization_operands_complete(expression):
    source = (
        'const payload={valueOf:consume};const errors=[];'
        f'errors.push({expression});console.log(JSON.stringify(errors));'
    )
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.cjs"], "file_cache": {"case.cjs": source}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] == "completed"
