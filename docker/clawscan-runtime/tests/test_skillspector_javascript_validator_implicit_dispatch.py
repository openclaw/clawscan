"""An optional closed proof must account for every implicit JS invocation."""

import pytest

from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner

CASES = {
    "await_thenable": 'const payload={then:consume,command:`tou${"ch"} /tmp/marker`};const errors=[];errors.push(`${Boolean(await payload)}`);console.log(JSON.stringify(errors));',
    "await_logical_thenable": 'const payload={then:consume,command:`tou${"ch"} /tmp/marker`};const errors=[];errors.push(`${Boolean(await (payload||1))}`);console.log(JSON.stringify(errors));',
    "await_private_thenable": 'const payload={then:consume,command:`tou${"ch"} /tmp/marker`};function value(){return payload;}const errors=[];errors.push(`${Boolean(await value())}`);console.log(JSON.stringify(errors));',
    "inherited_getter": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const errors=[];errors.push(`${Boolean(payload.value)}`);console.log(JSON.stringify(errors));',
    "inherited_subscript_getter": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const errors=[];errors.push(`${Boolean(payload["value"])}`);console.log(JSON.stringify(errors));',
    "inherited_iterator": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const errors=[];errors.push(`${Boolean([...payload])}`);console.log(JSON.stringify(errors));',
    "unknown_object_spread": 'const payload=carrier;const errors=[];errors.push(`x${Boolean({...payload})}`);console.log(JSON.stringify(errors));',
    "unknown_array_spread": 'const payload=carrier;const errors=[];errors.push(`x${Boolean([...payload])}`);console.log(JSON.stringify(errors));',
    "destructuring_getter": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const {value}=payload;const errors=[];errors.push(`${Boolean(value)}`);console.log(JSON.stringify(errors));',
    "destructuring_iterator": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const [value]=payload;const errors=[];errors.push(`${Boolean(value)}`);console.log(JSON.stringify(errors));',
    "delegated_generator": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};function* values(){yield* payload;}const errors=[];errors.push(`${Boolean(values().next())}`);console.log(JSON.stringify(errors));',
    "async_iteration": 'const payload={__proto__:carrier,command:`tou${"ch"} /tmp/marker`};const errors=[];for await(const value of payload)errors.push(`${Boolean(value)}`);console.log(JSON.stringify(errors));',
    "unknown_tag": 'const errors=[];errors.push(`${Boolean(tag`x${1}`)}`);console.log(JSON.stringify(errors));',
    "native_tag_shape": 'import {readFile} from "node:fs/promises";const errors=[];errors.push(`${Boolean(readFile`x${1}`)}`);console.log(JSON.stringify(errors));',
    "proxy_receiver": 'const payload=new Proxy({command:`tou${"ch"} /tmp/marker`},carrier);const errors=[];errors.push(`${Boolean(payload.value)}`);console.log(JSON.stringify(errors));',
}


@pytest.mark.parametrize("source", CASES.values(), ids=CASES)
def test_unknown_implicit_dispatch_remains_incomplete(source):
    report = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.mjs"], "file_cache": {"case.mjs": source}}, [tool]
    )
    assert report["inspection_ledger"][0]["outcome"] != "completed"
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()


@pytest.mark.parametrize("expression", [
    '`${await "value"}`',
    '`${await Number("1")}`',
    '`${Boolean({value:1}.value)}`',
    '`${[...["a","b"]].join(",")}`',
])
def test_known_native_operands_keep_the_closed_proof(expression):
    source = f'const errors=[];errors.push({expression});console.log(JSON.stringify(errors));'
    report = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.mjs"], "file_cache": {"case.mjs": source}}, [tool]
    )
    assert report["inspection_ledger"][0]["outcome"] == "completed"
