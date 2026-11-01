"""Closed native capability uses must preserve the full-module proof."""
import pytest
from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tm, static_runner

IMPORT = "import {open} from 'node:fs/promises'; "
DATA = "`state-${1}.tmp`"

def report(source):
    return static_runner.run_static_patterns_with_ledger(
        {'components':['entry.cjs'], 'file_cache':{'entry.cjs':source}}, [tm])

def owners(source):
    owner = JavaScriptSourceOwnership(source, lambda: None)
    return {owner.data_literal(i) for i in range(len(source)) if owner.data_literal(i) is not None}

@pytest.mark.parametrize('callee', ['open', '(open)', '((open))'])
def test_closed_native_callee_preserves_owned_path(callee):
    source = IMPORT + f"{callee}({DATA}, 'wx');"
    assert len(owners(source)) == 1
    assert report(source)['inspection_ledger'][0]['outcome'] == 'completed'

def test_parenthesized_alias_still_has_every_use_proof():
    source = IMPORT + f"const fd=(open); (fd)({DATA}, 'wx');"
    assert len(owners(source)) == 1

def test_safe_independent_omission_has_real_completed_ledger():
    tail = '\n'.join(f'const value{i}={i};' for i in range(400))
    source = 'const options=["--recursive","--force","/tmp/build"];\n/*)`*/\n' + IMPORT + f"(open)({DATA}, 'wx');\n" + tail
    assert report(source)['inspection_ledger'][0]['outcome'] == 'completed'
    assert len(owners(source)) == 1

@pytest.mark.parametrize('effect', [
    'unknownEffect();', '(unknownEffect)();',
    'this.unrelated;',
    'consume(open);', 'consume((open));',
    'open=eval;',
    "require.cache['node:fs/promises']={exports:{open:eval}};",
    'Object.assign(open,{call:eval});', '(Object.assign)(open,{call:eval});',
    'Object.defineProperty(open,"call",{value:eval});', '(Object.defineProperty)(open,"call",{value:eval});',
    'Object.setPrototypeOf(open,evil);', '(Object.setPrototypeOf)(open,evil);',
    '(open.call)(null,"data");', '(open.apply)(null,["data"]);', '(open.bind)(null);',
    'eval(code);', '(eval)(code);', 'Function(code);', '(Function)(code);',
    'setTimeout(code,0);', '(setTimeout)(code,0);',
    "import {tmpdir} from 'node:os';", "import {fileURLToPath} from 'node:url';",
    '(Object.getPrototypeOf)(open);', '(Object.getOwnPropertyDescriptor)(open,"call");',
    'const x={get value(){return 1}};', 'globalThis.open=eval;',
])
def test_parentheses_do_not_skip_module_identity_and_effect_guards(effect):
    source = IMPORT + effect + f" (open)({DATA}, 'wx');"
    assert owners(source) == set()

@pytest.mark.parametrize('source', [
    IMPORT + "const p=`state-${1}.tmp`; (open)(p,'r'); unknown(p);",
    IMPORT + "const p=`state-${1}.tmp`; (open)(p,'r'); assert.deepEqual(p);",
    "const {open}=require('node:fs/promises'); (open)(`state-${1}.tmp`,'r');",
    "function read(fetch,id){return (fetch)(`/api/${id}`)}read(execute,id);",
    "export class Client{read(id){return this.request(`/api/${id}`)}}",
    IMPORT + "const x={get path(){return eval(code)}};(open)(`${x.path}`,'r');",
    IMPORT + "const x={[Symbol.toPrimitive](){return eval(code)}};(open)(`${x}`,'r');",
    "const x={toJSON(){return eval(code)}};(fetch)(`/api/${JSON.stringify(x)}`);",
    "function positive(value){if(!/^[1-9]\\d*$/.test(String(value)))throw Error('POSITIVE_ID_REQUIRED');return value;}export function read(id){return (fetch)(`/api/${positive(id)}`)}",
    "window.fetch(`/api/${id}`);",
    "(eval)(`${command} -rf /`);", "(Function)(`${command} -rf /`)();",
    "(setTimeout)(`${command} -rf /`,0);", "exec(`${command} -rf /`);",
])
def test_opaque_consumers_stay_partial_without_ownership(source):
    assert report(source)['inspection_ledger'][0]['outcome'] == 'partial'
    assert owners(source) == set()

def test_original_destructive_findings_are_unchanged():
    raw = 'exec("rm -rf /");'
    source = IMPORT + f"(open)({DATA}, 'wx');\n" + raw
    actual = report(source)['findings']
    assert any(f.rule_id == 'TM1' and f.severity == 'HIGH' for f in actual)
