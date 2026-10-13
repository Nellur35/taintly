from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _scan(tmp_path: Path, workflow: str) -> set[str]:
    target = tmp_path / ".github" / "workflows" / "refs.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(workflow, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return {finding.rule_id for finding in findings}


def _taint_workflow(job_if: str, step_if: str) -> str:
    return (
        "on: [push, pull_request_target]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        f"    if: {job_if}\n"
        "    steps:\n"
        "      - name: run title\n"
        f"        if: {step_if}\n"
        "        env:\n"
        "          VALUE: ${{ github.event.pull_request.title }}\n"
        '        run: eval "$VALUE"\n'
    )


@pytest.mark.parametrize(
    ("job_if", "step_if", "expected"),
    [
        (
            "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main'",
            "github.event_name == 'pull_request_target' && github.ref != 'refs/heads/main'",
            False,
        ),
        (
            "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main'",
            "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main'",
            True,
        ),
        (
            "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main'",
            "github.event_name == 'pull_request_target' && github.ref == inputs.branch",
            True,
        ),
    ],
    ids=["contradictory-ref-guards", "compatible-ref-guards", "unknown-ref-retains"],
)
def test_same_job_ref_guard_conjunction_is_fail_open_for_unknowns(
    tmp_path: Path, job_if: str, step_if: str, expected: bool
) -> None:
    rule_ids = _scan(tmp_path, _taint_workflow(job_if, step_if))
    assert ("CHAIN-GH-103" in rule_ids) is expected


def _crossjob_workflow(
    *,
    producer_if: str,
    consumer_if: str = "",
    authority_steps: str,
    step_local_reader: bool = False,
) -> str:
    consumer_guard = f"    if: {consumer_if}\n" if consumer_if else ""
    if step_local_reader:
        consumer_binding = ""
        authority_steps = (
            "      - name: read output on main ref\n"
            "        if: github.ref == 'refs/heads/main'\n"
            "        env:\n"
            "          VALUE: ${{ needs.produce.outputs.val }}\n"
            '        run: echo "$VALUE"\n' + authority_steps
        )
    else:
        consumer_binding = "    env:\n      VALUE: ${{ needs.produce.outputs.val }}\n"
    return (
        "on: [pull_request_target, issues]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        f"    if: {producer_if}\n"
        "    outputs:\n"
        "      val: ${{ steps.source.outputs.val }}\n"
        "    steps:\n"
        '      - id: source\n        run: echo "val=hello" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        + consumer_guard
        + consumer_binding
        + "    steps:\n"
        + authority_steps
    )


def test_crossjob_job_and_authority_ref_contradiction_removes_chain(tmp_path: Path) -> None:
    body = _crossjob_workflow(
        producer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        consumer_if="github.event_name == 'issues' && github.ref == 'refs/heads/release'",
        authority_steps=(
            "      - name: write issue\n"
            "        if: github.event_name == 'issues' && github.ref == 'refs/heads/release'\n"
            "        run: gh issue edit 1 --add-label constant\n"
        ),
    )
    assert "CHAIN-GH-105" not in _scan(tmp_path, body)


def test_job_env_can_reach_one_compatible_authority_among_disjoint_steps(
    tmp_path: Path,
) -> None:
    body = _crossjob_workflow(
        producer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        consumer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        authority_steps=(
            "      - name: disjoint write\n"
            "        if: github.ref == 'refs/heads/release'\n"
            "        run: gh issue edit 1 --add-label constant\n"
            "      - name: compatible write\n"
            "        if: github.ref == 'refs/heads/main'\n"
            "        run: gh release create v1 --notes constant\n"
        ),
    )
    assert "CHAIN-GH-105" in _scan(tmp_path, body)


def test_unknown_authority_alternative_does_not_prove_ref_disjointness(
    tmp_path: Path,
) -> None:
    body = _crossjob_workflow(
        producer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        consumer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        authority_steps=(
            "      - name: known disjoint write\n"
            "        if: github.ref == 'refs/heads/release'\n"
            "        run: gh issue edit 1 --add-label constant\n"
            "      - name: unresolved write\n"
            "        if: inputs.should_run\n"
            "        run: gh release create v1 --notes constant\n"
        ),
    )
    assert "CHAIN-GH-105" in _scan(tmp_path, body)


def test_step_local_output_reference_cannot_borrow_sibling_authority(tmp_path: Path) -> None:
    body = _crossjob_workflow(
        producer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        consumer_if="github.event_name == 'issues' && github.ref == 'refs/heads/main'",
        authority_steps=(
            "      - name: sibling authority under release ref\n"
            "        if: github.ref == 'refs/heads/release'\n"
            "        run: gh issue edit 1 --add-label constant\n"
        ),
        step_local_reader=True,
    )
    assert "CHAIN-GH-105" not in _scan(tmp_path, body)
