"""Canonical shell ownership must retain actual executable uncertainty."""

import os
import shlex
import shutil
import subprocess
import time

import pytest
from skillspector import shell_source
from skillspector.inspection_ledger import LedgerOutcome
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tm
from skillspector.nodes.analyzers import static_runner


@pytest.fixture
def canonical_parser():
    executable = shutil.which("shfmt")
    assert executable is not None, "Pinned Bash parser is required in the runtime"
    assert subprocess.check_output([executable, "--version"], text=True).strip() == "v3.14.1"


def ledger(content):
    return static_runner.run_static_patterns_with_ledger(
        {"components": ["scripts/example.sh"], "file_cache": {"scripts/example.sh": content}},
        [tm],
    )


@pytest.mark.parametrize(
    "content",
    [
        '[[ "$(printf \'%s\' "$VALUE")" == expected ]]\n',
        '# 👋 the command can use "$(cat)" as data\n' + "# padding\n" * 1000 + "true\n",
        "COUNT=$(find \"$DIR\" -name '*.md' | wc -l | tr -d ' ')\n"
        + "# padding\n" * 1000
        + "true\n",
        '# Unicode → offsets\r\n[[ "$(printf \'%s\' "$VALUE")" != expected ]]\r\n',
    ],
)
def test_complete_nonexecuting_source_roles(canonical_parser, content):
    assert shell_source.ShellSourceOwnership(content, lambda: None).command_starts is not None
    result = ledger(content)
    assert result["inspection_ledger"][0]["outcome"] is LedgerOutcome.COMPLETED


@pytest.mark.parametrize(
    "content",
    [
        '"$(printf \'%s\' "$CMD")" -rf /\n',
        'exec "$CMD" -rf /\n',
        'eval "$(printf \'%s\' "$CMD")"\n',
        'bash -c "$CMD"\n',
        '[[ "$( $CMD -rf / )" == expected ]]\n',
        '[[ "$(eval "$CMD")" == expected ]]\n',
        'if [[ "$(printf \'%s\' "$VALUE")" == expected ]]; then "$CMD" -rf /; fi\n',
        "eval \"$(python3 - <<'PY'\nprint(input())\nPY\n)\"\n",
        'bash -c \'"$(printf "%s" "$CMD")" -rf /\'\n',
        'CMD=$(printf \'%s\' "$VALUE"); eval "$CMD"\n',
        'alias check=eval\ncheck "$(printf \'%s\' "$CMD")"\n',
        '[[ "$(printf \'%s\' "$VALUE")" == x ]]; rm -rf /\n',
    ],
)
def test_executable_constructions_remain_partial_or_high(canonical_parser, content):
    result = ledger(content)
    completed = result["inspection_ledger"][0]["outcome"] is LedgerOutcome.COMPLETED
    high = any(
        finding.rule_id == "TM1" and str(finding.severity).upper() == "HIGH"
        for finding in result["findings"]
    )
    assert not completed or high


@pytest.mark.parametrize("operator", [":=", "="])
@pytest.mark.parametrize("spacing", ["", " ", "\t"])
def test_comparison_parameter_assignments_retain_secondary_evaluation(canonical_parser, operator, spacing):
    # Integer/nameref attributes can cause an assignment's value to be read as
    # arithmetic source even though its outer context is a string comparison.
    content = (
        'PAYLOAD=\'a[$(eval "$CMD")0]\'; unset number; declare -i number; '
        '[[ "${number' + operator + spacing + '$(printf \'%s\' "$PAYLOAD")}" == 0 ]]\n'
    )
    ownership = shell_source.ShellSourceOwnership(content, lambda: None)
    opener = content.index("$(printf")
    assert not ownership.is_noncommand_start(opener)
    result = ledger(content)
    assert result["inspection_ledger"][0]["outcome"] is not LedgerOutcome.COMPLETED


@pytest.mark.parametrize("declaration", ["declare -i", "typeset -i", "local -i"])
def test_quoted_declaration_values_do_not_gain_quote_ownership(canonical_parser, declaration):
    content = (
        declaration + ' "number=$(printf \'%s\' "$PAYLOAD")"\n'
        + "# padding\n" * 1000 + "true\n"
    )
    ownership = shell_source.ShellSourceOwnership(content, lambda: None)
    outer_closing_quote = content.index(')"') + 1
    assert not ownership.is_noncommand_start(outer_closing_quote)
    assert ledger(content)["inspection_ledger"][0]["outcome"] is not LedgerOutcome.COMPLETED


def test_unavailable_parser_retains_existing_lexical_limit(monkeypatch):
    monkeypatch.setattr(shell_source.shutil, "which", lambda _: None)
    content = '[[ "$(printf \'%s\' "$VALUE")" == expected ]]\n'
    assert shell_source.ShellSourceOwnership(content, lambda: None).command_starts is None
    assert tm.has_bounded_parse_exhaustion(content, lambda: None, file_type="shell")


@pytest.mark.parametrize(
    "content", ['echo "unterminated', 'echo "👋"\n' * 20_000],
    ids=["unterminated", "over-source-budget"],
)
def test_malformed_or_oversized_source_has_no_ownership(canonical_parser, content):
    assert shell_source.ShellSourceOwnership(content, lambda: None).command_starts is None


def test_outer_runtime_budget_propagates():
    class BudgetExceededError(RuntimeError):
        pass

    def exhausted():
        raise BudgetExceededError

    with pytest.raises(BudgetExceededError):
        shell_source.ShellSourceOwnership("true\n", exhausted)


def test_parser_output_budget_is_bounded(canonical_parser, monkeypatch):
    monkeypatch.setattr(shell_source, "MAX_AST_BYTES", 64)
    assert shell_source.ShellSourceOwnership("echo harmless\n", lambda: None).command_starts is None


@pytest.mark.parametrize("error", [TimeoutError, ValueError, RuntimeError])
def test_outer_budget_failure_inside_parser_is_not_availability_fallback(canonical_parser, error):
    calls = 0

    def exhausted():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise error("outer deadline")

    with pytest.raises(error, match="outer deadline"):
        shell_source.ShellSourceOwnership("true\n", exhausted)


def test_parser_timeout_reaps_the_actual_helper(monkeypatch, tmp_path):
    pid_file = tmp_path / "helper.pid"
    executable = tmp_path / "parser"
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' $$ > " + shlex.quote(str(pid_file)) + "\nexec /bin/sleep 60\n"
    )
    executable.chmod(0o700)
    monkeypatch.setattr(shell_source.shutil, "which", lambda _: str(executable))
    monkeypatch.setattr(shell_source, "PARSER_SECONDS", 0.1)
    started = time.monotonic()
    assert shell_source.ShellSourceOwnership("true\n", lambda: None).command_starts is None
    assert time.monotonic() - started < 2
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
