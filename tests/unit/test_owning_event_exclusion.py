"""Source-level event contradictions, with live and unresolved controls."""

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.staticguard import WorkflowContext


def workflow(on="pull_request_target", job_if=None, step_if=None):
    job_guard = f"    if: {job_if}\n" if job_if else ""
    step_guard = f"        if: {step_if}\n" if step_if else ""
    return (
        f"name: Owning event compatibility\non: {on}\n"
        "permissions:\n  contents: read\njobs:\n  inspect:\n"
        "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
        f"{job_guard}    steps:\n"
        "      - run: echo \"${{ github.event.pull_request.body }}\"\n"
        f"{step_guard}"
    )


def injection_lines(source):
    rules = [r for r in load_rules_for_platform(Platform.GITHUB) if r.id == "SEC4-GH-004"]
    assert len(rules) == 1
    return [f.line for f in scan_file(".github/workflows/ci.yml", rules, _content=source)]


@pytest.mark.parametrize(
    "source",
    [
        workflow(job_if="github.event_name == 'issues'"),
        workflow(step_if="github.event_name == 'issues'"),
        workflow(on="[pull_request_target, push]", job_if="github.event_name == 'issues'"),
        workflow(
            on="[pull_request_target, issues]",
            job_if="github.event_name == 'pull_request_target'",
            step_if="github.event_name == 'issues'",
        ),
    ],
)
def test_contradictory_owning_guards_cannot_execute_sink(source):
    assert injection_lines(source) == []


@pytest.mark.parametrize(
    "source",
    [
        workflow(job_if="github.event_name == 'pull_request_target'"),
        workflow(job_if="vars.REVIEW_ENABLED == 'yes'"),
        workflow(on="[pull_request_target, issues]", job_if="github.event_name == 'issues'"),
        workflow(on="workflow_call", job_if="github.event_name == 'pull_request_target'"),
        workflow(on="[pull_request_target, workflow_call]", job_if="github.event_name == 'issues'"),
        workflow(on="[pull_request_target, unknown_event]", job_if="github.event_name == 'issues'"),
        workflow(job_if="github.event_name == 'issues'").replace(
            "on: pull_request_target\n", "on: pull_request_target\non: issues\n"
        ),
        workflow(job_if="github.event_name == 'issues'").replace(
            "    if: github.event_name == 'issues'\n",
            "    if: github.event_name == 'issues'\n    if: true\n",
        ),
        workflow(job_if="github.event_name == 'issues'").replace(
            "name: Owning event compatibility\n", "name: Owning event compatibility\nx-note: &note marker\n"
        ),
        workflow(job_if="github.event_name == 'issues'") + "x-note: [unfinished\n",
    ],
)
def test_live_or_unresolved_structure_retains_candidate(source):
    assert injection_lines(source)


def test_step_guard_does_not_hide_sibling_or_root_trigger():
    source = workflow(step_if="github.event_name == 'issues'") + (
        "      - run: echo \"${{ github.event.pull_request.body }}\"\n"
    )
    last_line = len(source.splitlines())
    assert injection_lines(source) == [last_line]
    rules = [r for r in load_rules_for_platform(Platform.GITHUB) if r.id == "SEC4-GH-002"]
    assert any(f.rule_id == "SEC4-GH-002" for f in scan_file(".github/workflows/ci.yml", rules, _content=source))


def test_block_scalar_physical_line_keeps_owner():
    source = workflow(job_if="github.event_name == 'issues'").replace(
        '      - run: echo "${{ github.event.pull_request.body }}"\n',
        '      - run: |\n          printf start\n          echo "${{ github.event.pull_request.body }}"\n',
    )
    assert injection_lines(source) == []


def test_runtime_guard_is_visibly_unresolved_in_whole_finding():
    source = workflow(job_if="vars.REVIEW_ENABLED == 'yes'")
    rules = [r for r in load_rules_for_platform(Platform.GITHUB) if r.id == "SEC4-GH-004"]
    finding, = scan_file(".github/workflows/ci.yml", rules, _content=source)
    assert finding.review_needed
    assert any("runtime" in note.lower() and "guard" in note.lower() for note in finding.context_notes)
    assert "including write access and all bound secrets" not in finding.threat_narrative


def test_explicit_known_repository_guard_does_not_become_runtime_unknown():
    source = workflow(job_if="github.repository == 'example/review'")
    rules = [r for r in load_rules_for_platform(Platform.GITHUB) if r.id == "SEC4-GH-004"]
    finding, = scan_file(
        ".github/workflows/ci.yml", rules, _content=source,
        repoctx=WorkflowContext(repository="example/review"),
    )
    assert not finding.review_needed
    assert not any("requires runtime" in note for note in finding.context_notes)
