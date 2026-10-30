"""Native diagnostic values do not give file/command outputs ownership."""

import pytest
from skillspector.nodes.analyzers import (
    static_patterns_tool_misuse as tool,
    static_runner,
)


def complete(source):
    return (
        static_runner.run_static_patterns_with_ledger(
            {"components": ["validator.mjs"], "file_cache": {"validator.mjs": source}},
            [tool],
        )["inspection_ledger"][0]["outcome"]
        == "completed"
    )


@pytest.mark.parametrize(
    "source",
    [
        'import {writeFileSync} from "node:fs";const n=1;console.error(`value: ${n}`);writeFileSync("report.json","{}");',
        'import {resolve} from "node:path";const p=resolve("input.html");console.error(`Input file not found: ${p}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",["--format","json","input.html"],{encoding:"utf8"});console.error(`stderr: ${r.stderr.trim()}`);',
    ],
)
def test_proven_scalar_template_has_its_own_console_consumer(source):
    assert complete(source)


@pytest.mark.parametrize(
    "source",
    [
        'import {spawnSync} from "node:child_process";import {writeFileSync} from "node:fs";spawnSync("sh",["-c","mkfifo report; sh >/dev/null 2>&1 <report &"],{encoding:"utf8"});writeFileSync("report",JSON.stringify(["$","(touch marker)"].join("")));',
        'import {spawnSync} from "node:child_process";import {writeFileSync} from "node:fs";spawnSync("sh",["-c","(while ! test -f report; do sleep 1; done; sh report) >/dev/null 2>&1 &"],{encoding:"utf8"});writeFileSync("report",JSON.stringify(["$","(touch marker)"].join("")));',
        'import {exec} from "node:child_process";const x=process.argv[2];exec(`run ${x}`);',
        "const console={error(x){eval(x)}};const n=1;console.error(`value: ${n}`);",
        "const c=console;c.error=eval;const n=1;console.error(`value: ${n}`);",
        'String.prototype.trim=eval;import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"utf8"});console.error(`stderr: ${r.stderr.trim()}`);',
        'const object={toString(){eval(process.argv[2]);return "x"}};console.error(`value: ${object}`);',
        'import {writeFileSync} from "node:fs";writeFileSync("report",JSON.stringify(["$","(touch marker)"].join("")));console.error(`value: ${1}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"utf8",shell:true});console.error(`stderr: ${r.stderr.trim()}`);',
        'import {resolve} from "node:path";const p=resolve({toString:unknown});console.error(`path: ${p}`);',
        'import "untrusted";console.error(`value: ${1}`);',
        "const o={};unknown(o);console.error(`value: ${1}`);",
    ],
)
def test_executable_or_unproved_value_use_stays_incomplete(source):
    assert not complete(source)


@pytest.mark.parametrize(
    "source",
    [
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"utf8"});r.stderr={trim:evil};console.error(`stderr: ${r.stderr.trim()}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{get encoding(){return "utf8"}});console.error(`stderr: ${r.stderr.trim()}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{...opts,encoding:"utf8"});console.error(`stderr: ${r.stderr.trim()}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"buffer"});console.error(`stderr: ${r.stderr.trim()}`);',
        'import {spawnSync} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"utf8"});console.error(`stderr: ${r.stderr.trim()}`,process.argv[2]);',
        'import {writeFileSync} from "node:fs";const m=`value: ${1}`;console.error(m);writeFileSync("report",m);',
        'import {writeFileSync} from "node:fs";writeFileSync("report","$"+"(touch marker)");console.error(`value: ${1}`);',
        'import {spawnSync,exec} from "node:child_process";const r=spawnSync("vnu",[],{encoding:"utf8"});console.error(`stderr: ${r.stderr.trim()}`);exec(r.stderr);',
        'const data=JSON.parse("{}",evil);console.error(`data: ${data}`);',
        'const data=JSON.parse("{}");data.toString=evil;console.error(`data: ${data}`);',
    ],
)
def test_diagnostic_type_evidence_does_not_own_other_effects(source):
    assert not complete(source)


@pytest.mark.parametrize(
    "source",
    [
        "with({console:{error:eval}}){const n=1;console.error(`x:${n}`)}",
        "with({console:{error:consume}}){const n=1;console.error(`x:${n}`)}",
        "console.error`x:${1}`;",
        "delete console.error;const n=1;console.error(`x:${n}`);",
        "console.error++;const n=1;console.error(`x:${n}`);",
        "console?.error(`x:${process.argv[2]}`);",
        "console.error?.(`x:${process.argv[2]}`);",
        "try{throw 1}catch(console){console.error(`x:${1}`)}",
        "const values=[1];for(const console of values){console.error(`x:${1}`)}",
        "function f(console){console.error(`x:${1}`)}f();",
    ],
)
def test_unproved_grammar_or_lexical_console_stays_incomplete(source):
    assert not complete(source)


@pytest.mark.parametrize(
    "source",
    [
        'import {execSync} from "node:child_process";for(let value of [""]){value={split:execSync};console.error(`out:${value.split("echo diagnostic")[0]}`);}',
        'import {execSync} from "node:child_process";for(let value of [""]){const alias={split:execSync};value=alias;console.error(`out:${value.split("echo diagnostic")[0]}`);}',
        'import {execSync} from "node:child_process";for(const value of [""]){value={split:execSync};console.error(`out:${value.split("echo diagnostic")[0]}`);}',
        'import {execSync} from "node:child_process";const [value]=[""];value={split:execSync};console.error(`out:${value.split("echo diagnostic")[0]}`);',
        'import {execSync} from "node:child_process";let [value]=[""];value={split:execSync};console.error(`out:${value.split("echo diagnostic")[0]}`);',
        'import {execSync} from "node:child_process";const [value]=[""];let alias=value;alias={split:execSync};console.error(`out:${alias.split("echo diagnostic")[0]}`);',
        'for(const value in [""]){console.error(`out:${value.split("")[0]}`);}',
    ],
)
def test_reassigned_or_enumerated_binding_does_not_inherit_element_type(source):
    from skillspector.javascript_source import JavaScriptSourceOwnership

    # Check this public ownership boundary independently of unrelated shell
    # parser incompleteness that can otherwise mask an unsafe ownership grant.
    assert JavaScriptSourceOwnership(source, lambda: None).unsupported_values()
    assert not complete(source)


@pytest.mark.parametrize(
    "source",
    [
        'for(const value of ["text"]){console.error(`out:${value.trim()}`);}',
        'for(const value of ["text"]){const alias=value;console.error(`out:${alias.trim()}`);}',
        'const [value]=["text"];console.error(`out:${value.trim()}`);',
        "const [value]=process.argv.slice(2);console.error(`out:${value.trim()}`);",
    ],
)
def test_immutable_for_of_or_const_destructuring_preserves_scalar_provenance(source):
    assert complete(source)
