"""Whole-workflow dead-suppression integration tests.

When every job in a GitHub Actions workflow is statically
dead (every ``if:`` evaluates to STATIC_FALSE), the engine
suppresses all findings in the file — including trigger-level
findings on the ``on:`` block that per-job suppression
deliberately leaves alone.

Field-test evidence: trigger-level findings across multiple
fully-dead workflows on real-world repositories, each
producing SEC4-GH-001 / SEC4-GH-002 at the
``pull_request_target:`` declaration despite the workflow
being unable to run.  Whole-workflow suppression closes that
residue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.staticguard import WorkflowContext


def _scan_findings(tmp_path: Path) -> list:
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    return [f for r in reports for f in r.findings]


def _write_workflow(tmp_path: Path, name: str, content: str) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(content, encoding="utf-8")


def test_fully_dead_workflow_suppresses_trigger_findings(tmp_path):
    """Every job dead -> no findings, including trigger-level."""
    _write_workflow(
        tmp_path,
        "dead.yml",
        (
            "on:\n"
            "  pull_request_target:\n"
            "    types: [labeled]\n"
            "jobs:\n"
            "  build:\n"
            "    if: false\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n'
        ),
    )
    findings = _scan_findings(tmp_path)
    assert not findings, (
        "Whole-dead workflow must produce zero findings; got "
        f"{[(f.rule_id, f.line) for f in findings]}"
    )


def test_partially_dead_workflow_keeps_trigger_findings(tmp_path):
    """Mix of dead and live jobs -> workflow is not whole-dead;
    trigger-level findings still fire."""
    _write_workflow(
        tmp_path,
        "mixed.yml",
        (
            "on:\n"
            "  pull_request_target:\n"
            "    types: [labeled]\n"
            "jobs:\n"
            "  dead_one:\n"
            "    if: false\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo dead\n"
            "  live_one:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo live\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "SEC4-GH-001" in rule_ids or "SEC4-GH-002" in rule_ids, (
        f"Mixed-dead workflow must keep trigger-level findings; got {sorted(rule_ids)}"
    )


def test_all_runtime_guards_workflow_keeps_findings(tmp_path):
    """All jobs RUNTIME -> not whole-dead -> trigger findings remain."""
    _write_workflow(
        tmp_path,
        "runtime.yml",
        (
            "on:\n"
            "  pull_request_target:\n"
            "    types: [labeled]\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      deploy:\n"
            "        type: boolean\n"
            "jobs:\n"
            "  conditional:\n"
            "    if: ${{ inputs.deploy }}\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "SEC4-GH-001" in rule_ids or "SEC4-GH-002" in rule_ids, (
        f"RUNTIME-guarded workflow must keep trigger findings; got {sorted(rule_ids)}"
    )


@pytest.mark.parametrize("scope", ["job", "step"])
@pytest.mark.parametrize(("operator", "live"), [("==", True), ("!=", False)])
def test_case_varied_repository_guard_preserves_live_input_execution(
    tmp_path, scope, operator, live
):
    """Real input-injection rules must follow Actions' case-insensitive guard."""
    guard = f"if: github.repository_owner {operator} 'myorg'"
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        f"    {guard if scope == 'job' else 'name: build'}\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - {guard if scope == 'step' else 'name: input'}\n"
        '        run: echo "${{ github.event.pull_request.title }}"\n'
    )
    _write_workflow(tmp_path, "case.yml", content)
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(
        str(tmp_path),
        rules,
        Platform.GITHUB,
        explicit_github_repoctx=WorkflowContext("MyOrg/MyRepo", "MyOrg"),
    )
    findings = [f for report in reports for f in report.findings]
    assert any(f.rule_id == "SEC4-GH-004" for f in findings) is live
    if scope == "job" and not live:
        assert findings == []


@pytest.mark.parametrize(("operator", "live"), [("==", True), ("!=", False)])
def test_identical_unicode_literals_do_not_create_dead_job_findings(tmp_path, operator, live):
    _write_workflow(
        tmp_path,
        "unicode.yml",
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        f"    if: ${{{{ 'é' {operator} 'é' }}}}\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.pull_request.title }}"\n',
    )
    findings = _scan_findings(tmp_path)
    assert not any(f.rule_id == "ENGINE-ERR" for f in findings)
    assert any(f.rule_id == "SEC4-GH-004" for f in findings) is live
    if not live:
        assert findings == []
