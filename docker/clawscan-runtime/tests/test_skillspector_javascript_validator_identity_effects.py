"""Owner admission must prove identities and every callback input use."""

import pytest

from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector.nodes.analyzers import static_runner

CASES = {
    "global_escape": 'leaked = new RegExp(`con${"sole"}.log(1)`).source;',
    "global_pattern_escape": '({value: leaked} = {value: new RegExp(`con${"sole"}.log(1)`).source});',
    "intrinsic_shorthand_write": '({RegExp} = {RegExp: Worker}); new RegExp(`data:text/javascript,postMessage(${"42"})`);',
    "intrinsic_nested_write": '([{RegExp}] = [{RegExp: Worker}]); new RegExp(`data:text/javascript,postMessage(${"42"})`);',
    "intrinsic_default_write": '({RegExp = Worker} = {}); new RegExp(`data:text/javascript,postMessage(${"42"})`);',
    "annex_b_constructor": 'const captured=[]; {function RegExp(value){captured.push(value);}} new RegExp(`x${1}`);',
    "callback_file_content": 'import {writeFile} from "node:fs/promises"; const commands=[`tou${"ch"} /tmp/marker`]; console.log(commands.map(command=>Number(writeFile("startup.sh",command))).join(","));',
    "filter_file_content": 'import {writeFile} from "node:fs/promises"; const commands=[`tou${"ch"} /tmp/marker`]; console.log(commands.filter(command=>Boolean(writeFile("startup.sh",command))).join(","));',
    "callback_parameter_write": 'const commands=[`tou${"ch"} /tmp/marker`]; console.log(commands.map(command=>Number(command="changed")).join(","));',
    "callback_string_transfer": 'import {writeFile} from "node:fs/promises"; const commands=[`tou${"ch"} /tmp/marker`]; console.log(commands.map(command=>Number(writeFile("startup.sh",String(command)))).join(","));',
    "callback_regexp_transfer": 'import {writeFile} from "node:fs/promises"; const commands=[`tou${"ch"} /tmp/marker`]; console.log(commands.map(command=>Number(writeFile("startup.sh",new RegExp(command).source))).join(","));',
    "local_regexp_transfer": 'import {writeFile} from "node:fs/promises"; const source=new RegExp(`tou${"ch"} /tmp/marker`).source; writeFile("startup.sh",source);',
}


@pytest.mark.parametrize("source", CASES.values(), ids=CASES)
def test_unknown_identity_escape_or_callback_input_remains_incomplete(source):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["case.cjs"], "file_cache": {"case.cjs": source}}, [tool]
    )
    assert result["inspection_ledger"][0]["outcome"] != "completed"
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()
