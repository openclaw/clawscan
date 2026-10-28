"""Closed validator data flow must not admit executable callback values."""

import pytest

from skillspector.javascript_source import JavaScriptSourceOwnership
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool, static_runner


VALIDATOR = r'''
import { readFile } from "node:fs/promises";
function validate(md) {
  const errors = [];
  for (const n of ["A", "B"]) {
    if (!new RegExp(`^${n}`, "m").test(md)) errors.push(`Missing ${n}`);
  }
  const matches = [...md.matchAll(/(\d+)/g)];
  const numbers = matches.map((m) => Number(m[1]));
  const extra = matches.filter((m) => !/^1/.test(m[1]));
  errors.push(`Numbers ${numbers.join(",")}; extra ${extra.map((m) => m[1]).join(",")}`);
  function check(heads, label) {
    for (let i = 0; i < heads.length; i += 1) {
      errors.push(`${label}: ${heads[i][1].match(/\d+/)?.[0] ?? "?"}`);
    }
  }
  check(matches, "headings");
  const start = Number(matches[0]?.[1]);
  const end = Number(matches[1]?.[1]);
  errors.push(`Duration ${(end - start).toFixed(3)}`);
  return { errors };
}
try {
  const files = process.argv.slice(2);
  const md = await readFile(files[0], "utf8");
  const result = validate(md);
  console.log(JSON.stringify(result));
} catch (error) {
  console.log(JSON.stringify({ errors: [String(error?.message ?? error)] }));
}
'''


def inspect(source):
    result = static_runner.run_static_patterns_with_ledger(
        {"components": ["validator.mjs"], "file_cache": {"validator.mjs": source}}, [tool]
    )
    return result["inspection_ledger"][0], result["findings"]


def test_closed_native_validator_completes_with_original_template_bytes():
    event, _ = inspect(VALIDATOR)
    assert event["outcome"] == "completed"


@pytest.mark.parametrize("addition", [
    'console.log = (text) => eval(text);',
    'RegExp = class { constructor(text) { eval(text); } test() { return true; } };',
    'Array.prototype.join = function () { eval(this[0]); };',
    'Number.prototype.toFixed = function (text) { eval(text); };',
    'String = (value) => eval(value);',
    'Object.defineProperty(Array.prototype, "push", { value: eval });',
])
def test_changed_native_identity_remains_incomplete(addition):
    event, findings = inspect(addition + "\n" + VALIDATOR)
    assert event["outcome"] != "completed" or any(
        f.severity in {"HIGH", "CRITICAL"} for f in findings
    )


@pytest.mark.parametrize("use", [
    "unknown(errors)",
    "unknownAlias(errors)",
    "exec(errors[0])",
    "setTimeout(() => exec(errors[0]), 0)",
])
def test_private_array_cannot_escape_to_unproved_calls(use):
    source = VALIDATOR.replace("return { errors };", use + "; return { errors };")
    event, findings = inspect(source)
    assert event["outcome"] != "completed" or any(
        f.severity in {"HIGH", "CRITICAL"} for f in findings
    )


@pytest.mark.parametrize("prefix", [
    'const console = { log: eval };',
    'const RegExp = class { constructor(text) { eval(text); } test() {} };',
    'const Number = eval;',
    'const String = eval;',
])
def test_shadowed_native_names_do_not_grant_ownership(prefix):
    event, _ = inspect(prefix + "\n" + VALIDATOR)
    assert event["outcome"] != "completed"


@pytest.mark.parametrize("statement", [
    'new Number(`value ${input}`);',
    'new Boolean(`value ${input}`);',
    'new String(`value ${input}`);',
    'new validate(`value ${input}`);',
])
def test_unproved_constructors_keep_their_own_template_incomplete(statement):
    source = VALIDATOR + "\n" + statement
    start = len(VALIDATOR)
    spans = JavaScriptSourceOwnership(source, lambda: None).unsupported_values()
    assert any(a >= start for a, _ in spans)


@pytest.mark.parametrize("statement", [
    'const cp=process.getBuiltinModule("child_process"); cp.execSync(String.fromCharCode(114,109,32,45,114,102,32,47));',
    'const cp=process.getBuiltinModule("child_process"); const words=["r","m -rf /"]; cp.execSync(words.map((x)=>x).join(""));',
    'const cp=process.getBuiltinModule("child_process"); const words=["r","m -rf /"]; cp.execSync(words.join(""));',
    'function hidden(value) { return value; } const alias=hidden; unknown(alias(`r${"m"} -rf /`));',
    'const cp=process.getBuiltinModule("child_process"); let alias=console.log; alias=cp.execSync; alias(`r${"m"} -rf /`);',
])
def test_actual_executable_construction_remains_individually_opaque(statement):
    source = VALIDATOR + "\n" + statement
    start = len(VALIDATOR)
    spans = JavaScriptSourceOwnership(source, lambda: None).unsupported_values()
    assert any(a >= start for a, _ in spans)
