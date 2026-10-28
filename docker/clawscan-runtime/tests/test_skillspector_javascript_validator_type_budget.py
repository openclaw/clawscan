"""Small shared type graphs must remain inside the scanner's runtime budget."""

import json
import subprocess
import sys

import pytest

from skillspector.javascript_native_values import NativeValidatorValues


@pytest.mark.parametrize("error", [False, True])
def test_primitive_union_visits_check_the_runtime_budget(error):
    class DeadlineError(Exception):
        pass

    remaining = 5

    def step():
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise DeadlineError

    owner = NativeValidatorValues(
        data=b"",
        nodes=[],
        parents={},
        definition=lambda _: None,
        capability=lambda _: None,
        private_function=lambda _: None,
        reads=lambda _: [],
        bindings=lambda _, **kwargs: [],
        ambient_intrinsic=lambda *_: None,
        step=step,
    )
    kind = ("string",)
    for _ in range(8):
        kind = ("either", kind, kind)
    with pytest.raises(DeadlineError):
        owner.primitive(kind, error=error)


@pytest.mark.parametrize("operation", ["primitive", "equality"])
def test_shared_source_value_graph_does_not_expand_exponentially(operation):
    # Run the real source owner in a child: an uncharged recursive traversal
    # must fail this test without pinning the entire test or scanner process.
    script = r"""
import json,sys
from skillspector.javascript_source import JavaScriptSourceOwnership
if sys.argv[1] == "primitive":
    lines = ['const a0=`x${1}`, b0=1;']
    for i in range(1, 29):
        lines.append(f'const a{i}=a{i-1}||b{i-1}; const b{i}=b{i-1}||a{i-1};')
    lines.append('console.log(String(a28));')
else:
    lines = ['const a0=`x${1}`, b0=1, c0=`y${2}`, d0=2;']
    for i in range(1, 28):
        lines.append(f'const a{i}=a{i-1}||b{i-1}, b{i}=b{i-1}||a{i-1};')
        lines.append(f'const c{i}=c{i-1}||d{i-1}, d{i}=d{i-1}||c{i-1};')
    lines.append('console.log(String(a27||c27));')
source='\n'.join(lines)
checks=0
def check():
    global checks
    checks += 1
owner=JavaScriptSourceOwnership(source,check)
incomplete=owner.analysis_incomplete()
unsupported=owner.unsupported_values()
print(json.dumps({'incomplete':incomplete,'unsupported':len(unsupported),'checks':checks}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, operation],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    report = json.loads(result.stdout)
    assert report["checks"] > 0


@pytest.mark.parametrize("count, exhausted", [(160, False), (200, True)])
def test_repeated_lexical_lookups_preserve_unknown_call_evidence(count, exhausted):
    from skillspector.javascript_source import JavaScriptSourceOwnership

    source = 'import {helper} from "./unknown.mjs";\n' + "\n".join(
        f'function fn{i}(value){{ const text=`x${{value}}`; return helper(String(text)); }}'
        for i in range(count)
    )
    owner = JavaScriptSourceOwnership(source, lambda: None)
    assert owner.analysis_incomplete() is exhausted
    spans = owner.unsupported_values()
    if exhausted:
        assert not spans
    else:
        assert len(spans) == count
        assert all(source[start:end] == "`x${value}`" for start, end in spans)
