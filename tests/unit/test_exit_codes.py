"""Regression: README's exit-code table matches __main__.py behaviour.

The CI-gate documentation in README.md commits to specific exit codes
for specific outcomes.  Code-and-docs drift here would be a fail-open
footgun for any CI gate that depends on the contract.  These tests
exercise each documented code via subprocess so the exit-code itself
is what's asserted, not a Python-level intermediate.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


def _run(args: list[str], cwd: Path | None = None) -> int:
    """Run taintly with args, return exit code."""
    result = subprocess.run(
        [sys.executable, "-m", "taintly", *args],
        cwd=str(cwd) if cwd else str(ROOT),
        capture_output=True,
        timeout=120,
    )
    return result.returncode


def test_clean_scan_exits_zero(tmp_path: Path):
    """Empty repo with no workflows → exit 0."""
    code = _run([str(tmp_path)])
    assert code == 0, f"expected 0 (clean scan), got {code}"


def test_invalid_argument_exits_two(tmp_path: Path):
    """Unknown flag → argparse → exit 2.

    Note: code 2 is shared with the CRITICAL-severity exit path
    elsewhere in the CLI; this test isolates the argparse path by
    using a flag argparse will reject before any scan runs.
    """
    code = _run(["--no-such-flag", str(tmp_path)])
    assert code == 2, f"expected 2 (argparse error), got {code}"


def test_config_error_exits_three(tmp_path: Path):
    """Explicit ``--config`` pointing at a missing file → exit 3.

    The auto-discovery path is intentionally lenient (it warns and
    proceeds on malformed YAML), so the reliable trigger for the
    config-error code is an explicit ``--config <path>`` referring
    to a non-existent file.
    """
    code = _run(["--config", str(tmp_path / "nonexistent.yml"), str(tmp_path)])
    assert code == 3, f"expected 3 (config error: missing --config file), got {code}"


def test_findings_above_fail_on_exits_one(tmp_path: Path):
    """Findings above --fail-on severity → exit 1.

    HIGH-severity finding in the workflow + ``--fail-on HIGH`` puts
    the scan on the fail-on path before any of the severity-summary
    fallback branches can fire.
    """
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "bad.yml").write_text(
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    code = _run([str(tmp_path), "--fail-on", "HIGH"])
    # SEC4-GH-001 fires CRITICAL on this shape, but --fail-on HIGH
    # routes through the explicit threshold-comparison path which
    # exits 1.  Without --fail-on the CRITICAL severity would route
    # through the worst-severity fallback (exit 2).
    assert code == 1, f"expected 1 (findings >= --fail-on), got {code}"


def test_self_test_clean_exits_zero():
    """--self-test on the clean rule pack → exit 0."""
    code = _run(["--self-test"])
    assert code == 0, f"expected 0 (clean self-test), got {code}"


def test_self_test_with_unknown_rule_exits_three():
    """--self-test --rule <nonexistent> → exit 3 (configuration error)."""
    code = _run(["--self-test", "--rule", "DOES-NOT-EXIST-001"])
    assert code == 3, f"expected 3 (unknown rule ID), got {code}"


def test_self_test_failure_exits_ten(tmp_path: Path, monkeypatch):
    """--self-test with a deliberately-broken sample → exit 10.

    Approach: run the CLI in a subprocess with a synthetic test
    sample injected via a sitecustomize-style import hook.  The hook
    wraps ``run_self_test`` to return one failed result, simulating
    a positive sample that didn't fire.
    """
    helper = tmp_path / "fake_self_test.py"
    helper.write_text(
        "import sys\n"
        "from taintly.testing import self_test as st\n"
        "_orig = st.run_self_test\n"
        "def _fake(rules):\n"
        "    out = _orig(rules)\n"
        "    out.append(st.TestResult(\n"
        "        rule_id='SEC3-GH-001', test_type='positive',\n"
        "        sample='deliberate failure', expected='trigger',\n"
        "        actual='no_trigger', passed=False))\n"
        "    return out\n"
        "st.run_self_test = _fake\n"
        "from taintly.__main__ import main\n"
        "main()\n"
    )
    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, str(helper), "--self-test"],
        cwd=str(ROOT),
        capture_output=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 10, (
        f"expected 10 (self-test failure), got {result.returncode}"
    )


def test_coverage_warning_exits_eleven(tmp_path: Path):
    """A scan that completes but hits the ReDoS file-size cap emits
    an ENGINE-ERR finding → exit 11.

    Trigger: a workflow file larger than _MAX_SAFE_TEXT_LEN (50KB).
    The scanner runs per-line rules but skips full-content patterns,
    surfacing an ENGINE-ERR finding.  No HIGH/CRITICAL findings, so
    the exit-code path falls through to the coverage-warning branch.
    """
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # Build a file > 50_000 bytes that's entirely benign comments
    # plus a stub workflow header.  No real findings should fire.
    big_comment = "# benign comment\n" * 4000  # ~68 KB
    (wf_dir / "huge.yml").write_text(
        big_comment
        + "on: push\n"
        "jobs:\n"
        "  noop:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    code = _run([str(tmp_path)])
    assert code == 11, (
        f"expected 11 (coverage degraded via ENGINE-ERR), got {code}"
    )


@pytest.mark.timeout(120)
def test_self_test_mutation_failure_exits_twelve(tmp_path: Path):
    """--self-test --mutate with an injected surviving mutation → exit 12.

    Same import-hook approach as the exit-10 test: wrap
    ``run_mutation_tests`` to inject one failing result, simulating
    a mutation the rule pack didn't kill.
    """
    helper = tmp_path / "fake_mutate.py"
    helper.write_text(
        "import sys\n"
        "from taintly.testing import self_test as st\n"
        "_orig = st.run_mutation_tests\n"
        "def _fake(rules):\n"
        "    out = _orig(rules)\n"
        "    out.append(st.TestResult(\n"
        "        rule_id='SEC3-GH-001', test_type='mutation_positive',\n"
        "        sample='deliberate survivor', expected='trigger',\n"
        "        actual='no_trigger', passed=False, mutation_op='fake'))\n"
        "    return out\n"
        "st.run_mutation_tests = _fake\n"
        "from taintly.__main__ import main\n"
        "main()\n"
    )
    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, str(helper), "--self-test", "--mutate", "--rule", "SEC3-GH-001"],
        cwd=str(ROOT),
        capture_output=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 12, (
        f"expected 12 (mutation regression), got {result.returncode}"
    )
