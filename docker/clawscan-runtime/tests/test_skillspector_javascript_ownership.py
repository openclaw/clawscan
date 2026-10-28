"""Native data value uses can prove source ownership; executable strings cannot."""

import pytest

from skillspector.inspection_ledger import LedgerOutcome, LedgerReason
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tm
from skillspector.nodes.analyzers import static_runner

TAIL = "\n".join(f"const value{index} = {index};" for index in range(400))
OPTIONS = 'const options = ["--recursive", "--force", "/tmp/build"];\n'
# Minimized from the historical signature-format comment in pi-evox identity.mjs.
COMMENT = "/*)`*/\n"


def ledger(source, extension="mjs"):
    path = f"scripts/helper.{extension}"
    return static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: source}}, [tm]
    )


@pytest.mark.parametrize("extension", ["js", "mjs", "cjs"])
@pytest.mark.parametrize("comment", [COMMENT, "// )`\n", "/* 日本語🦞 )` */\r\n"])
def test_comment_cannot_open_a_shell_word_into_host_code(extension, comment):
    row = ledger(OPTIONS + comment + TAIL, extension)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.COMPLETED
    assert "reason_code" not in row


@pytest.mark.parametrize(
    "statement",
    [
        "exec(`${command} -rf /`);",
        "exec(`${command} ${flags} /`);",
        "exec(`${command} -rf /*`);",
        "exec(`${command} -rf ~`);",
        "const command = `${tool} -rf /`; exec(command);",
        r"exec(`${command}\x20-rf\x20/`);",
        r"exec(`${command}\u0020-rf\u0020/`);",
        r"exec(`${command}\u{20}-rf\u{20}/`);",
        "exec(`${command}${flags} /`);",
        "exec(`${command} ${flags}/`);",
        "exec(`${command} -rf ${target}`);",
        "exec(`${command} --recursive --force ${target}`);",
        "exec(`${a}${b}${c}/`);",
        "exec(`rm -${flags} /home/`);",
        'const command = `${tool} ${"-rf /home/"}`; exec(command);',
        "exec(`'${command}' -rf /*`);",
        "exec(`${tool} ${id()}`);",
        "const cmd = `echo ready; ${tool}${suffix} -rf ${root}${path}`; exec(cmd);",
        'const cmd = (useRm ? `r${suffix}` : "echo") + " -rf /"; exec(cmd);',
        "const cmd = `rm ${flags}f ${root}home/`; exec(cmd);",
        'const cmd = (0, `rm`) + " -r" + "f /home/"; exec(cmd);',
        'import {exec as run} from "node:child_process"; run(`${cmd}${flags} /`);',
        "function log(value) { exec(value); } log(`${cmd}${flags} /`);",
        "let log = console.log; log = exec; log(`${cmd}${flags} /`);",
        "const value = `${cmd}${flags} /`; console.log(value); exec(value);",
    ],
)
def test_comment_ownership_does_not_grant_template_or_value_ownership(statement):
    row = ledger(OPTIONS + COMMENT + statement + "\n" + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL
    assert row["reason_code"] in {
        LedgerReason.STATIC_PARSE_LIMIT,
        LedgerReason.OPAQUE_CONTENT,
    }


def test_comment_ownership_retains_actual_high_destructive_finding():
    source = OPTIONS + COMMENT + 'exec("rm -rf /");\n' + TAIL
    findings = ledger(source)["findings"]
    assert any(f.rule_id == "TM1" and f.severity == "HIGH" for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        OPTIONS + "/* unterminated )`\n" + TAIL,
        OPTIONS + COMMENT + "const broken = ;\n" + TAIL,
        "#!/bin/sh\n" + OPTIONS + COMMENT + TAIL,
    ],
)
def test_ambiguous_source_keeps_conservative_coverage(source):
    assert tm.has_bounded_parse_exhaustion(source, lambda: None, file_type="javascript")


def test_fragment_cannot_claim_whole_module_comment_ownership():
    assert tm.has_bounded_parse_exhaustion(
        OPTIONS + COMMENT + TAIL,
        lambda: None,
        file_type="javascript",
        complete_context=False,
    )


def test_other_language_does_not_get_javascript_comment_ownership():
    assert tm.has_bounded_parse_exhaustion(
        OPTIONS + COMMENT + TAIL, lambda: None, file_type="shell"
    )


@pytest.mark.parametrize(
    "statement",
    [
        "throw new Error(`Repeated option ${key}`);",
        "const NativeError = Error; throw new NativeError(`Repeated option ${key}`);",
        "fetch(`${base}/api`);",
        "const endpoint = `${base}/api`; fetch(endpoint);",
        "let url = `${base}/api`; fetch(url);",
        "let detail = ''; detail = String.fromCharCode(111, 107); throw new Error(detail);",
        "process.stdout.write(`Result: ${result}\\n`);",
        "const out = process.stdout; const write = out.write; write(`Result: ${result}`);",
        (
            'import {open as fd, rename as move, rm as remove} from "node:fs/promises"; '
            'const temporary = `${file}.${id}.tmp`; fd(temporary, "r"); '
            'move(temporary, "output"); remove(temporary);'
        ),
    ],
)
def test_proven_native_data_value_uses_have_complete_real_ledger(statement):
    row = ledger(OPTIONS + COMMENT + statement + "\n" + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize(
    "statement",
    [
        "function test(Error) { throw new Error(`option ${key}`); }",
        "function NativeError(value) {} throw new NativeError(`option ${key}`);",
        "function replacement(value) {} Error = replacement; throw new Error(`option ${key}`);",
        "function sink(value) {} const E = Error; sink(E); throw new E(`option ${key}`);",
        "function sink(run) { const out = process.stdout; out['write'] = run; out.write(`result ${key}`); }",
        "function sink(run) { const out = process.stdout; ({write: out.write} = run); out.write(`result ${key}`); }",
        "function sink(run) { Object.assign(process.stdout, {write: run}); process.stdout.write(`result ${key}`); }",
        "function fetch(value) { return value; } fetch(`${base}/api`);",
        "const url = `${base}/api`; fetch(url); other(url);",
        "let url = `${base}/api`; fetch(url); execute(url);",
        "let detail = ''; detail = String.fromCharCode(114, 109); obj.run(detail);",
        "export const url = `${base}/api`;",
        "function result() { return `${base}/api`; }",
        "const url = tag`${base}/api`; fetch(url);",
        'import {open} from "untrusted-fs"; open(`${file}.tmp`);',
        'import * as fs from "node:fs"; fs.open(`${file}.tmp`);',
        'import {open} from "node:fs/promises"; const file = `${base}.tmp`; open(file); execute(file);',
        "const E = Error.constructor; throw new E(`option ${key}`);",
        "setTimeout(runtimeCommand); throw new Error(`option ${key}`);",
        "const load = import('node:child_process'); throw new Error(`option ${key}`);",
        "globalThis['Error'] = run; throw new Error(`option ${key}`);",
        "throw new Error(`option ${unknown()}`);",
        "function stringify(value) { return this.run(value); } throw new Error(`option ${stringify(command)}`);",
        "with (scope) { throw new Error(`option ${key}`); }",
        "const original = JSON.stringify; function sink(value) {} sink(original); throw new Error(`option ${JSON.stringify(key)}`);",
        "function f(run) { const encode = JSON; encode['stringify'] = run; throw new Error(`option ${encode.stringify(key)}`); }",
    ],
)
def test_unknown_mutable_or_escaping_capabilities_keep_partial_coverage(statement):
    row = ledger(OPTIONS + COMMENT + statement + "\n" + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL
    assert row["reason_code"] in {
        LedgerReason.STATIC_PARSE_LIMIT,
        LedgerReason.OPAQUE_CONTENT,
    }


def test_native_data_ownership_keeps_raw_high_finding_and_original_line():
    source = "// 日本語🦞\n" + "throw new Error(`rm -rf / ${detail}`);\n" + TAIL
    findings = ledger(source)["findings"]
    high = [f for f in findings if f.rule_id == "TM1" and f.severity == "HIGH"]
    assert high
    assert all(f.start_line == 2 for f in high)


@pytest.mark.parametrize(
    "constant,limit", [("MAX_SOURCE_BYTES", 8), ("MAX_NODES", 2), ("MAX_DEPTH", 2)]
)
def test_parser_bounds_never_grant_ownership(monkeypatch, constant, limit):
    from skillspector import javascript_source as owner

    monkeypatch.setattr(owner, constant, limit)
    row = ledger(OPTIONS + COMMENT + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL


def test_value_use_budget_never_grants_ownership(monkeypatch):
    from skillspector import javascript_values as owner

    monkeypatch.setattr(owner, "MAX_PROOF_STEPS", 2)
    row = ledger(OPTIONS + COMMENT + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL


def test_missing_parser_never_grants_ownership(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "tree_sitter_javascript", None)
    row = ledger(OPTIONS + COMMENT + TAIL)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL


def test_shared_runtime_deadline_propagates():
    from skillspector.javascript_source import JavaScriptSourceOwnership

    def stopped():
        raise TimeoutError("test deadline")

    owner = JavaScriptSourceOwnership(OPTIONS + COMMENT + TAIL, stopped)
    with pytest.raises(TimeoutError, match="test deadline"):
        owner.unsupported_values()


def test_native_parse_deadline_keeps_conservative_result(monkeypatch):
    from skillspector import javascript_source as owner

    monkeypatch.setattr(owner, "PARSE_TIMEOUT_MICROS", 1)
    row = ledger(OPTIONS + COMMENT + TAIL * 10)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL


def test_ownership_does_not_change_process_warning_filters():
    import warnings

    from skillspector.javascript_source import JavaScriptSourceOwnership

    before = list(warnings.filters)
    owner = JavaScriptSourceOwnership(OPTIONS + COMMENT + TAIL, lambda: None)
    owner.unsupported_values()
    assert warnings.filters == before


def closure_ledger(statement):
    path = "scripts/helper.mjs"
    source = "throw new Error(`Repeated option ${key}`);\n" + statement + "\n" + TAIL
    return static_runner.run_static_patterns_with_ledger(
        {"components": [path], "file_cache": {path: source}}, [tm]
    )["inspection_ledger"][0]


@pytest.mark.parametrize(
    "statement",
    [
        'const parts=["r","m"]; const p=Array.prototype; p.join=run; throw new Error(`value ${parts.join("")}`);',
        'const parts=["r","m"]; const p=Object.getPrototypeOf([]); p.join=run; throw new Error(`value ${parts.join("")}`);',
        'const parts=["r","m"]; Array["prototype"].join=run; throw new Error(`value ${parts.join("")}`);',
        r'const parts=["r","m"]; Array["proto\u0074ype"].join=run; throw new Error(`value ${parts.join("")}`);',
        "function message(){const record={text:`${cmd}${flags} /`};return record;} obj.run(message());",
        "function message(){const record={};record.text=`${cmd}${flags} /`;return record;} obj.run(message());",
        "function message(){return `${cmd}${flags} /`;} fetch(message()); obj.run(message());",
        "export function message(){return `${cmd}${flags} /`;} fetch(message());",
        'export let value=""; value=`${cmd}${flags} /`; fetch(value);',
        'function f(){if(flag){const target={};} target.join=run;} const parts=["r","m"]; throw new Error(`value ${parts.join("")}`);',
        'function record(){return {};} record=run; const target=record(); target.join=run; const parts=["r","m"]; throw new Error(`value ${parts.join("")}`);',
    ],
)
def test_native_or_private_values_cannot_escape_to_unknown_code(statement):
    row = closure_ledger(statement)
    assert row["outcome"] == "partial"
    assert row["reason_code"] == "opaque_content"


@pytest.mark.parametrize(
    "statement",
    [
        "function message(){const record={text:`Result ${value}`};return record;} process.stdout.write(JSON.stringify(message()));",
        "function message(){const record={};record.text=`Result ${value}`;return record;} process.stdout.write(JSON.stringify(message()));",
        'const values=["one","two"]; throw new Error(`Options: ${values.join(", ")}`);',
    ],
)
def test_private_source_values_have_only_proven_native_data_uses(statement):
    assert closure_ledger(statement)["outcome"] == "completed"


_EXECUTABLE_BOUNDARIES = [
    "function f({Error}) {throw new Error(`${command}${flags} /`);}",
    "function f(source) {({Error}=source); throw new Error(`${command}${flags} /`);}",
    "var {Error}=source; throw new Error(`${command}${flags} /`);",
    'const cmd=["rm", " -r", "f /home/"].join(""); ({run:exec}).run(cmd);',
    "const cmd=String.fromCharCode(114,109,32,45,114,102,32,47); obj.run(cmd);",
    'const cp=process.getBuiltinModule("child_process"); cp.execSync(process.argv.slice(2).join(" "));',
    "function f({fetch}, tool, flags) {fetch(`${tool}${flags} /`);}",
    "function f(run, tool, flags) {this.fetch=run; fetch(`${tool}${flags} /`);}",
    r"function f(\u0066etch, tool, flags) {fetch(`${tool}${flags} /`);}",
    'const parts=process.argv.slice(2); process.getBuiltinModule("child_process").exec(parts.join(" "));',
    r"function f(run, cmd, flags) {const f\u0065tch=run; fetch(`${cmd}${flags} /`);}",
    "function f(cmd,url){obj.run(cmd);fetch(url)} f(...[], `${a}${b}`);",
    'function f(cmd,url){obj.run(cmd);fetch(url)} f(/*comment*/ `${a}${b}`, "https://example.com");',
    'function f(run){Object.assign(this,{fetch:run});fetch(String.fromCharCode(114,109,32,45,114,102,32,47));} f(process.getBuiltinModule("child_process").execSync);',
    'import {execSync} from "node:child_process"; const encode=String.fromCharCode; execSync(encode(114,109,32,45,114,102,32,47));',
    'import {execSync} from "node:child_process"; export const cmd=String.fromCharCode(114,109,32,45,114,102,32,47); execSync(cmd);',
    "const cmd=String.fromCharCode(114,109,32,45,114,102,32,47); export {cmd}; obj.run(cmd);",
    "const record={set text(value){obj.run(value);}}; record.text=`${cmd}${flags} /`; process.stdout.write(JSON.stringify(record));",
    "function record(){return {set text(value){obj.run(value);}};} const target=record(); target.text=`${cmd}${flags} /`; process.stdout.write(JSON.stringify(target));",
    'const record={}; const proto={set text(value){obj.run(value);}}; const key="__proto__"; record[key]=proto; record.text=`${cmd}${flags} /`; process.stdout.write(JSON.stringify(record));',
    'const cmd=["rm", " -r", "f /home/"].reduce((a,b)=>a+b); obj.run(cmd);',
    "obj.run`${cmd}${flags} /`;",
    'function f(run){const encode=String.fromCharCode; Object.assign(this,{fetch:run}); fetch(encode(114,109,32,45,114,102,32,47));} f(process.getBuiltinModule("child_process").execSync);',
    'import fs from "node:fs"; fs.open=run; fs.open(`${cmd}${flags} /`);',
    'Number=process.getBuiltinModule("child_process").execSync; Number(String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47));',
    'for (const fetch of [process.getBuiltinModule("child_process").execSync]) fetch(String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47));',
    'let out={}; out=process.stdout; out.write=process.getBuiltinModule("child_process").execSync; process.stdout.write(String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47));',
    'import "node:os"; const {cmd}={cmd:String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47)}; obj.run(cmd);',
    'const runner={run:process.getBuiltinModule("child_process").execSync}; const make=()=>String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47); runner.run(make());',
    'function unused(){const write=process.stdout.write;} function install(run){this.write=run; write(String.fromCharCode(114,109,32,45,114,102,32,47,104,111,109,101,47));} install(process.getBuiltinModule("child_process").execSync);',
    "for (const fetch of [obj.run]) fetch(`${cmd}${flags} /`);",
    "function unused(){const write=process.stdout.write;} write(`${cmd}${flags} /`);",
    "if(true){function fetch(value){obj.run(value);}} fetch(`${cmd}${flags} /`);",
]


@pytest.mark.parametrize("statement", _EXECUTABLE_BOUNDARIES)
@pytest.mark.parametrize("tail", ["", TAIL], ids=["short", "long"])
@pytest.mark.parametrize(
    "imports",
    [
        "",
        'import {readFile} from "node:fs/promises";\n',
        'import {plugin} from "unsupported-module";\n',
        'import plugin from "unsupported-module";\n',
        'import * as plugin from "unsupported-module";\n',
    ],
)
def test_executable_constructions_keep_partial_coverage_across_import_boundaries(
    statement, tail, imports
):
    source = (
        imports
        + "throw new Error(`Repeated option ${key}`);\n"
        + statement
        + "\n"
        + tail
    )
    row = ledger(source)["inspection_ledger"][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL
    assert row["reason_code"] in {
        LedgerReason.OPAQUE_CONTENT,
        LedgerReason.STATIC_PARSE_LIMIT,
    }


@pytest.mark.parametrize(
    "source",
    [
        'import plugin from "unsupported-module"; export const metadata = `version ${version}`;',
        'import plugin from "unsupported-module"; export const metadata = plugin.describe("package");',
        'import * as plugin from "unsupported-module"; const metadata = `version ${version}`;',
        'import {plugin} from "unsupported-module"; function metadata() {return `version ${version}`;}',
    ],
)
def test_unsupported_imports_do_not_make_unobserved_metadata_newly_opaque(source):
    from skillspector.javascript_source import JavaScriptSourceOwnership

    owner = JavaScriptSourceOwnership(source, lambda: None)
    assert owner.unsupported_values() == ()
    if "`" in source:
        assert owner.data_literal(source.index("`")) is None


@pytest.mark.parametrize(
    "source",
    [
        'import plugin from "unsupported-module"; export const metadata = `version ${plugin.version()}`;',
        'import plugin from "unsupported-module"; const metadata = plugin.create("metadata");',
        'import plugin from "unsupported-module"; // )`\nexport const metadata = "value";',
    ],
)
def test_unsupported_import_fallback_never_grants_comment_or_literal_ownership(source):
    from skillspector.javascript_source import JavaScriptSourceOwnership

    owner = JavaScriptSourceOwnership(source, lambda: None)
    assert owner.unsupported_values() == ()
    assert all(
        owner.comment(index) is None and owner.data_literal(index) is None
        for index in range(len(source))
    )


@pytest.mark.parametrize(
    "module,constant,limit",
    [
        ("javascript_source", "MAX_SOURCE_BYTES", 8),
        ("javascript_source", "MAX_NODES", 2),
        ("javascript_source", "MAX_DEPTH", 2),
        ("javascript_values", "MAX_PROOF_STEPS", 2),
    ],
)
def test_constructed_execution_bounds_are_incomplete_without_a_shell_tail(
    monkeypatch, module, constant, limit
):
    import importlib

    monkeypatch.setattr(
        importlib.import_module("skillspector." + module), constant, limit
    )
    row = ledger("obj.run(String.fromCharCode(114,109,32,45,114,102,32,47));")[
        "inspection_ledger"
    ][0]
    assert row["outcome"] == LedgerOutcome.PARTIAL
    assert row["reason_code"] == LedgerReason.STATIC_PARSE_LIMIT


def test_source_padding_cannot_remove_constructed_execution_limitation():
    from skillspector.javascript_source import MAX_SOURCE_BYTES

    source = "obj.run(String.fromCharCode(114,109,32,45,114,102,32,47));"
    assert tm.has_opaque_constructed_values(
        source, lambda: None, file_type="javascript"
    )
    assert tm.has_bounded_parse_exhaustion(
        source + "\n" * MAX_SOURCE_BYTES, lambda: None, file_type="javascript"
    )


def test_comment_nodes_do_not_change_safe_native_parameter_positions():
    source = "function output(/*comment*/ message) {process.stdout.write(message);} output(/*comment*/ `hello ${name}`);"
    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


@pytest.mark.parametrize(
    "source",
    [
        "function unused(){const fetch=run;} fetch(`https://${host}/api`);",
        "for (let fetch of []) {} fetch(`https://${host}/api`);",
        "function output(){const write=process.stdout.write;write(`result ${value}`);} output();",
    ],
)
def test_native_identity_uses_the_actual_lexical_binding(source):
    assert ledger(source)["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED
