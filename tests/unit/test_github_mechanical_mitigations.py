from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.engine import _is_maintainer_gated_only
from taintly.models import Severity
from taintly.staticguard import WorkflowContext

FIXTURES = Path(__file__).parents[1] / "fixtures" / "github" / "mechanical"


def _write_workflow(tmp_path: Path, content: str) -> Path:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    path = workflow_dir / "mechanical.yml"
    path.write_text(content, encoding="utf-8")
    return path


def _write_fixture_workflow(tmp_path: Path, fixture: str) -> Path:
    return _write_workflow(tmp_path, (FIXTURES / fixture).read_text(encoding="utf-8"))


def _sec4_gh_008_findings(path: Path, github_rules):
    return [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-008"]


def _workflow_dispatch_input(extra_trigger: str = "") -> str:
    return (
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      environment:\n"
        "        type: string\n"
        f"{extra_trigger}"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh ${{ inputs.environment }}\n"
    )


def test_dead_job_suppresses_findings(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "dead_job_literal_false.yml")

    findings = scan_file(str(path), github_rules)

    assert not [f for f in findings if f.rule_id == "SEC4-GH-004"]


def test_dead_step_inside_live_job_suppresses_only_that_step(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "dead_step_inside_live_job.yml")

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-004"]

    assert len(findings) == 1
    assert "body" in findings[0].snippet


def test_repo_mismatch_dead_job_suppresses_findings(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "dead_job_repo_mismatch.yml")
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    findings = scan_file(str(path), github_rules, repoctx=ctx)

    assert not [f for f in findings if f.rule_id == "SEC4-GH-008"]


def test_runtime_guard_does_not_suppress_findings(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "live_job_runtime_guard.yml")

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-004"]

    assert findings


def test_workflow_dispatch_input_downgrades_when_maintainer_only(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "workflow_dispatch_input_shell.yml")

    findings = _sec4_gh_008_findings(path, github_rules)

    assert findings
    assert {f.severity for f in findings} == {Severity.MEDIUM}
    assert all("Maintainer-gated trigger path" in f.calibration_reason for f in findings)


def test_dead_path_suppression_happens_before_maintainer_gated_downgrade(
    github_rules, tmp_path
):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      environment:\n"
        "        type: string\n"
        "jobs:\n"
        "  deploy:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh ${{ inputs.environment }}\n",
    )

    findings = _sec4_gh_008_findings(path, github_rules)

    assert findings == []


@pytest.mark.parametrize(
    "extra_trigger",
    [
        "  pull_request:\n",
        "  pull_request_target:\n",
        "  pull_request_review:\n",
        "  workflow_run:\n",
        "  workflow_call:\n",
    ],
)
def test_workflow_dispatch_input_stays_high_with_fork_reachable_trigger(
    github_rules, tmp_path, extra_trigger
):
    path = _write_workflow(
        tmp_path,
        _workflow_dispatch_input(extra_trigger),
    )

    findings = _sec4_gh_008_findings(path, github_rules)

    assert findings
    assert {f.severity for f in findings} == {Severity.HIGH}


def test_workflow_dispatch_input_stays_high_with_inline_array_trigger(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on: [workflow_dispatch, pull_request]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh ${{ inputs.environment }}\n",
    )

    findings = _sec4_gh_008_findings(path, github_rules)

    assert findings
    assert {f.severity for f in findings} == {Severity.HIGH}


def test_workflow_dispatch_fixture_with_pull_request_stays_high(github_rules, tmp_path):
    path = _write_fixture_workflow(tmp_path, "workflow_dispatch_input_plus_pr.yml")

    findings = _sec4_gh_008_findings(path, github_rules)

    assert findings
    assert {f.severity for f in findings} == {Severity.HIGH}


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("on:\n  workflow_dispatch:\n", True),
        ("on:\n  release:\n", True),
        ("on:\n  schedule:\n", True),
        ("on:\n  push:\n    tags:\n      - v*\n", True),
        ("on:\n  push:\n    branches-ignore:\n      - '**'\n", True),
        ("on:\n  workflow_dispatch:\n  pull_request:\n", False),
        ("on:\n  workflow_dispatch:\n  pull_request_target:\n", False),
        ("on:\n  workflow_dispatch:\n  pull_request_review:\n", False),
        ("on:\n  workflow_dispatch:\n  pull_request_review_comment:\n", False),
        ("on:\n  workflow_dispatch:\n  workflow_run:\n", False),
        ("on:\n  workflow_dispatch:\n  workflow_call:\n", False),
        ("on: workflow_dispatch\n", False),
        ("on: [workflow_dispatch]\n", False),
        ("on: [workflow_dispatch, pull_request]\n", False),
        ("on:\n  pull_request:\n", False),
        ("name: no triggers\n", False),
    ],
)
def test_maintainer_gated_trigger_classification_matrix(content, expected):
    assert _is_maintainer_gated_only(content) is expected


def test_inline_workflow_dispatch_ref_name_stays_high_conservatively(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo Building $GITHUB_REF_NAME\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-018"]

    assert findings
    assert {f.severity for f in findings} == {Severity.HIGH}


def test_github_ref_name_downgrades_when_maintainer_only(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo Building $GITHUB_REF_NAME\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-018"]

    assert findings
    assert {f.severity for f in findings} == {Severity.MEDIUM}
    assert all("Maintainer-gated trigger path" in f.calibration_reason for f in findings)


def test_compound_repo_comparison_guard_does_not_suppress_findings(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  test:\n"
        "    if: github.repository == 'Nellur35/taintly' && success()\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n",
    )
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    findings = [
        f for f in scan_file(str(path), github_rules, repoctx=ctx) if f.rule_id == "SEC4-GH-004"
    ]

    assert findings
