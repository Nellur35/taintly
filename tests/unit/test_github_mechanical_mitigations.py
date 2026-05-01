from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Severity
from taintly.staticguard import WorkflowContext


def _write_workflow(tmp_path: Path, content: str) -> Path:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    path = workflow_dir / "mechanical.yml"
    path.write_text(content, encoding="utf-8")
    return path


def test_dead_job_suppresses_findings(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  dead:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
        "  live:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n",
    )

    findings = scan_file(str(path), github_rules)

    assert not [f for f in findings if f.rule_id == "SEC4-GH-004"]


def test_dead_step_inside_live_job_suppresses_only_that_step(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: false\n"
        "        run: echo \"${{ github.event.pull_request.title }}\"\n"
        "      - run: echo \"${{ github.event.pull_request.body }}\"\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-004"]

    assert len(findings) == 1
    assert "body" in findings[0].snippet


def test_repo_mismatch_dead_job_suppresses_findings(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  push:\n"
        "jobs:\n"
        "  release:\n"
        "    if: github.repository == 'other/repo'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"${{ github.event.inputs.version }}\"\n",
    )
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    findings = scan_file(str(path), github_rules, repoctx=ctx)

    assert not [f for f in findings if f.rule_id == "SEC4-GH-008"]


def test_runtime_guard_does_not_suppress_findings(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  test:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-004"]

    assert findings


def test_workflow_dispatch_input_downgrades_when_maintainer_only(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      environment:\n"
        "        type: string\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh ${{ inputs.environment }}\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-008"]

    assert findings
    assert {f.severity for f in findings} == {Severity.MEDIUM}


def test_workflow_dispatch_input_stays_high_with_fork_reachable_trigger(github_rules, tmp_path):
    path = _write_workflow(
        tmp_path,
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      environment:\n"
        "        type: string\n"
        "  pull_request:\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh ${{ inputs.environment }}\n",
    )

    findings = [f for f in scan_file(str(path), github_rules) if f.rule_id == "SEC4-GH-008"]

    assert findings
    assert {f.severity for f in findings} == {Severity.HIGH}
