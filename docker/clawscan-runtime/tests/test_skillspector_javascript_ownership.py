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
    assert row["reason_code"] == LedgerReason.STATIC_PARSE_LIMIT


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
        "export const url = `${base}/api`;",
        "function result() { return `${base}/api`; }",
        "let url = `${base}/api`; fetch(url);",
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
    assert row["reason_code"] == LedgerReason.STATIC_PARSE_LIMIT


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
        owner.is_code(0)


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
    owner.is_code(0)
    assert warnings.filters == before
