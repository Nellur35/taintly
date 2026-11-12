"""Regression: README's exit-code table matches __main__.py behaviour.

The CI-gate documentation in README.md commits to specific exit codes
for specific outcomes.  Code-and-docs drift here would be a fail-open
footgun for any CI gate that depends on the contract.  These tests
exercise each documented code via subprocess so the exit-code itself
is what's asserted, not a Python-level intermediate.
"""

from __future__ import annotations

import json
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


@pytest.mark.parametrize("write_baseline", [False, True])
def test_require_files_discloses_empty_scan(tmp_path: Path, write_baseline: bool):
    baseline = tmp_path / "baseline.json"
    args = ["--require-files", "--format", "json", "--no-config", str(tmp_path)]
    if write_baseline:
        baseline.write_bytes(b"existing baseline")
        args.extend(["--baseline", str(baseline)])
    result = subprocess.run(
        [sys.executable, "-m", "taintly", *args],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 11, result.stderr.decode(errors="replace")
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 0
    assert report["coverage_status"] == "incomplete"
    assert any("No CI configuration files found" in f["title"] for f in report["findings"])
    if write_baseline:
        assert baseline.read_bytes() == b"existing baseline"


def test_require_files_allows_scan_with_workflow(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\npermissions: {}\njobs: {}\n", encoding="utf-8")
    assert _run([str(tmp_path), "--require-files", "--no-config"]) == 0


@pytest.mark.parametrize("permissions, expected_exit", [("{}", 11), ("write-all", 1)])
def test_deep_yaml_flow_preserves_json_report(tmp_path: Path, permissions: str, expected_exit: int):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deep.yml").write_text(
        f"name: deep\non: push\npermissions: {permissions}\n"
        "jobs: {}\nextra: " + "[" * 1200 + "0" + "]" * 1200 + "\n",
        encoding="utf-8",
    )
    (workflows / "normal.yml").write_text("name: normal\non: push\njobs: {}\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path), "--format", "json", "--no-config"],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == expected_exit, result.stderr.decode(errors="replace")
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 2
    assert report["coverage_status"] == "incomplete"
    assert any(
        finding["rule_id"] == "ENGINE-ERR"
        and finding["line"] == 5
        and Path(finding["file"]).name == "deep.yml"
        for finding in report["findings"]
    )
    high_findings = {
        finding["rule_id"]
        for finding in report["findings"]
        if finding["severity"] in {"HIGH", "CRITICAL"}
    }
    assert high_findings == ({"SEC2-GH-001"} if permissions == "write-all" else set())


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


def test_critical_findings_exit_two_even_with_fail_on_high(tmp_path: Path):
    """CRITICAL findings → exit 2, even when ``--fail-on HIGH`` is set.

    The README documents:
      * 1 = HIGH (or fail-on threshold reached at sub-CRITICAL)
      * 2 = CRITICAL (or CLI argument error)

    CRITICAL takes precedence over fail-on so a CI gate can
    distinguish "the worst was HIGH" from "the worst was CRITICAL"
    regardless of where the fail-on bar is set.  Prior behaviour
    collapsed CRITICAL into exit 1 when fail-on was reached, which
    broke the documented contract on any config setting
    ``fail_on: HIGH`` (or lower).
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
    # SEC4-GH-001 fires CRITICAL on this shape.  CRITICAL wins
    # regardless of --fail-on.
    assert code == 2, f"expected 2 (CRITICAL severity wins), got {code}"


def test_high_findings_with_fail_on_high_exit_one(tmp_path: Path):
    """HIGH findings + ``--fail-on HIGH`` → exit 1.

    Sub-CRITICAL findings that reach the fail-on threshold route
    through the threshold-comparison path.  This is the
    fail-on-gates-CI shape: any HIGH-or-above triggers a non-zero
    exit, but CRITICAL still distinguishes via exit 2 (see
    :func:`test_critical_findings_exit_two_even_with_fail_on_high`).
    """
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # SEC2-GH-001 fires HIGH (not CRITICAL) on bare ``permissions:
    # write-all`` plus a single safe step.
    (wf_dir / "writeall.yml").write_text(
        "on: push\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    code = _run([str(tmp_path), "--fail-on", "HIGH"])
    assert code == 1, f"expected 1 (HIGH findings reach --fail-on HIGH), got {code}"


def test_self_test_clean_exits_zero():
    """--self-test on the clean rule pack → exit 0."""
    code = _run(["--self-test"])
    assert code == 0, f"expected 0 (clean self-test), got {code}"


_REVIEW_WORKFLOW = (
    "on: pull_request_target\n{permissions}\n"
    "jobs:\n  build:\n    runs-on: ubuntu-latest\n{job_fields}"
    "    steps:\n"
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    "        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n"
    "      - run: bash ./build.sh\n"
)


def _scan_json(workflows: Path, source: str, *flags: str):
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "review.yml").write_text(source, encoding="utf-8")
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(workflows.parent.parent),
            "--format",
            "json",
            "--no-config",
            *flags,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    return run.returncode, json.loads(run.stdout)


@pytest.mark.parametrize(
    ("permissions", "expected"),
    [
        ("permissions: {contents: read}", 0),
        ("permissions: {contents: write}", 2),
    ],
)
def test_review_advisory_preserves_report_and_confirmed_gate(tmp_path, permissions, expected):
    workflows = tmp_path / ".github" / "workflows"
    source = _REVIEW_WORKFLOW.format(permissions=permissions, job_fields="")
    default_exit, strict = _scan_json(workflows, source, "--fail-on", "HIGH")
    advisory_exit, advisory = _scan_json(
        workflows, source, "--fail-on", "HIGH", "--review-advisory"
    )
    assert default_exit == 2
    assert advisory_exit == expected
    assert strict["findings"] == advisory["findings"]
    assert strict["errors"] == advisory["errors"]
    assert any(f["severity"] == "CRITICAL" and f["review_needed"] for f in advisory["findings"])
    assert any(
        f["severity"] == "CRITICAL" and not f["review_needed"] for f in advisory["findings"]
    ) == (expected == 2)


def test_review_advisory_does_not_clear_incomplete_coverage(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "partial.yml").write_text(
        "on: push\npermissions: !!str write-all\njobs: {}\n", encoding="utf-8"
    )
    source = _REVIEW_WORKFLOW.format(permissions="permissions: {contents: read}", job_fields="")
    code, report = _scan_json(workflows, source, "--review-advisory")
    assert code == 11
    assert report["coverage_status"] == "incomplete"
    assert any(f["severity"] == "CRITICAL" and f["review_needed"] for f in report["findings"])


@pytest.mark.parametrize("job_scoped", [False, True])
def test_permission_presentation_preserves_decision(tmp_path, job_scoped):
    workflows = tmp_path / ".github" / "workflows"
    mapping = "permissions:\n  contents: write\n"
    inline = '"permissions": {"contents": "write"}\n'
    results = []
    for permissions in (mapping, inline):
        fields = (
            "".join("    " + line for line in permissions.splitlines(keepends=True))
            if job_scoped
            else ""
        )
        code, report = _scan_json(
            workflows,
            _REVIEW_WORKFLOW.format(
                permissions="" if job_scoped else permissions.rstrip(), job_fields=fields
            ),
        )
        critical = {
            f["rule_id"]: f["exploitability"]
            for f in report["findings"]
            if f["severity"] == "CRITICAL"
        }
        assert critical["SEC4-GH-001"] == "high"
        results.append((code, critical))
    assert results[0] == results[1]


def test_excluding_dependabot_does_not_calibrate_fork_path(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    findings = []
    for guard in ("", "    if: github.actor != 'dependabot[bot]'\n"):
        code, report = _scan_json(
            workflows,
            _REVIEW_WORKFLOW.format(permissions="permissions: {contents: write}", job_fields=guard),
        )
        assert code == 2
        finding = next(f for f in report["findings"] if f["rule_id"] == "SEC4-GH-001")
        findings.append((finding["exploitability"], finding["calibration_reason"]))
    assert findings == [("high", ""), ("high", "")]


@pytest.mark.parametrize(
    ("declaration", "expected_exit", "expected_ids"),
    [
        ("permissions:\n  contents: write\n", 1, ["SEC2-GH-005"]),
        ('"permissions": {"contents": "write"}\n', 1, ["SEC2-GH-005"]),
        ("permissions: {contents: read}\n", 0, []),
        ("", 1, ["SEC2-GH-002"]),
    ],
)
def test_workflow_write_scope_rule_reads_actual_mapping(
    tmp_path, declaration, expected_exit, expected_ids
):
    source = (
        f"on: push\n{declaration}jobs:\n"
        "  first:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"
        "      - run: |\n          cat <<'EOF'\n          permissions:\n"
        "            contents: write\n          EOF\n"
        "  second:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
        "    steps:\n      - run: echo done\n"
    )
    code, report = _scan_json(
        tmp_path / ".github" / "workflows",
        source,
        "--fail-on",
        "LOW",
    )
    assert code == expected_exit
    assert [finding["rule_id"] for finding in report["findings"]] == expected_ids


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
    """A scan past the actual chunked-coverage ceiling exits 11.

    The scanner still runs per-line rules, but file-scope searches cannot
    cover content past the bounded ceiling. With no HIGH/CRITICAL findings,
    the CLI must preserve its coverage-warning exit code.
    """
    from taintly.models import _CHUNK_COVERAGE_CEILING

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # Exceed the actual ceiling, rather than one successful chunk's size.
    line = "# benign comment\n"
    big_comment = line * (_CHUNK_COVERAGE_CEILING // len(line) + 100)
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


def test_timeout_scan_exits_eleven_not_clean(tmp_path: Path):
    """A clock-truncated scan must be distinguishable from a clean run at the
    exit-code layer — the bounded "scan incomplete" contract.

    ``--max-scan-seconds 0`` expires the per-file rule budget immediately, so
    every rule goes unevaluated and an ENGINE-ERR ("time-boxed") finding is
    emitted. With no real HIGH/CRITICAL, the exit code must fall through to the
    coverage-warning branch (11), never 0 — otherwise a timed-out scan would
    silently read as clean to a CI gate.

    A budget of exactly 0 is deterministic on every platform: the deadline is
    ``monotonic()`` captured before the loop, and ``monotonic()`` is
    non-decreasing, so the first iteration's ``monotonic() >= deadline`` is
    always true. A tiny *positive* budget (e.g. 0.0001) instead races the scan
    against the platform's clock resolution — flaky on Windows's coarse
    ``time.monotonic()`` tick, where a fast benign file can finish within one
    tick and never trip the deadline (observed: green locally, exit-0 on CI).
    """
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "x.yml").write_text(
        "on: push\n"
        "jobs:\n"
        "  noop:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    code = _run([str(tmp_path), "--max-scan-seconds", "0"])
    assert code == 11, f"expected 11 (scan incomplete via time-box), got {code}"


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
        "def _fake(rules, **kwargs):\n"
        "    out = _orig(rules, **kwargs)\n"
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
