"""Public-safe CHAIN-GH-101 GITHUB_TOKEN trigger-provenance regressions.

All workflows are synthetic. The PAT case checks only that the GITHUB_TOKEN
composite is not emitted; SEC4-GH-005 must still report the checkout token.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules
from taintly.workflow_corpus import WorkflowCorpus, WorkflowSummary


def _write_workflow(root: Path, filename: str, content: str) -> None:
    path = root / ".github" / "workflows" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _findings(root: Path, rule_id: str) -> list:
    reports = scan_repo(str(root), load_all_rules(), Platform.GITHUB)
    return [
        finding for report in reports for finding in report.findings if finding.rule_id == rule_id
    ]


def _workflow(
    trigger_block: str,
    *,
    job_permissions: str = "write",
    checkout: str = "      - uses: actions/checkout@v4\n",
    job_if: str = "",
) -> str:
    return (
        "name: Vulnerable\n"
        "on:" + trigger_block + "\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  vulnerable:\n    runs-on: ubuntu-latest\n"
        f"    permissions:\n      contents: {job_permissions}\n"
        + (f"    if: {job_if}\n" if job_if else "")
        + "    steps:\n"
        + checkout
        + "      - run: git push origin HEAD:main\n"
    )


@pytest.mark.parametrize(
    "trigger_block",
    [" pull_request", " [pull_request, push]"],
)
def test_plain_pull_request_write_declaration_does_not_upgrade_fork_token(
    tmp_path: Path, trigger_block: str
) -> None:
    """A trusted push trigger must not upgrade the PR execution's token."""
    _write_workflow(tmp_path, "ci.yml", _workflow(trigger_block))
    assert _findings(tmp_path, "CHAIN-GH-101") == []


def test_pull_request_target_with_write_token_retains_chain(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "ci.yml", _workflow(" pull_request_target"))
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


def test_issue_comment_with_write_token_retains_chain(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "ci.yml", _workflow(" issue_comment"))
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


@pytest.mark.parametrize(
    ("parent_name", "parent_event", "expected_count"),
    [
        ("PR Build", "pull_request", 1),
        ("Trusted Build", "push", 0),
    ],
)
def test_workflow_run_uses_named_parent_reachability(
    tmp_path: Path, parent_name: str, parent_event: str, expected_count: int
) -> None:
    child = _workflow(
        f"\n  workflow_run:\n    workflows: ['{parent_name}']\n    types: [completed]"
    )
    _write_workflow(tmp_path, "child.yml", child)
    _write_workflow(
        tmp_path,
        "parent.yml",
        (
            f"name: {parent_name}\n"
            f"on: {parent_event}\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ok\n"
        ),
    )
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == expected_count


def test_workflow_run_with_multiple_parent_workflows_is_external_if_any_parent_is(
    tmp_path: Path,
) -> None:
    child = _workflow("\n  workflow_run:\n    workflows: ['Trusted Build', 'PR Build']")
    _write_workflow(tmp_path, "child.yml", child)
    _write_workflow(
        tmp_path,
        "push-parent.yml",
        "name: Trusted Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    _write_workflow(
        tmp_path,
        "pr-parent.yml",
        "name: PR Build\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


def test_workflow_run_with_duplicate_parent_names_is_conservative(
    tmp_path: Path,
) -> None:
    child = _workflow("\n  workflow_run:\n    workflows: ['Shared Build']")
    _write_workflow(tmp_path, "child.yml", child)
    _write_workflow(
        tmp_path,
        "push-parent.yml",
        "name: Shared Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    _write_workflow(
        tmp_path,
        "pr-parent.yml",
        "name: Shared Build\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


def test_unresolved_workflow_run_parent_keeps_conservative_eligibility(
    tmp_path: Path,
) -> None:
    child = _workflow("\n  workflow_run:\n    workflows: ['Missing Build']\n    types: [completed]")
    _write_workflow(tmp_path, "child.yml", child)
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


def test_workflow_run_parent_cycle_keeps_conservative_eligibility(
    tmp_path: Path,
) -> None:
    first = _workflow("\n  workflow_run:\n    workflows: ['Second']\n    types: [completed]")
    second = (
        "name: Second\non:\n"
        "  workflow_run:\n    workflows: ['First']\n    types: [completed]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    )
    _write_workflow(tmp_path, "first.yml", first.replace("name: Vulnerable", "name: First"))
    _write_workflow(tmp_path, "second.yml", second)
    assert len(_findings(tmp_path, "CHAIN-GH-101")) == 1


def test_long_workflow_run_parent_chain_exhausts_budget_conservatively() -> None:
    parent_count = 270
    workflows = {}
    for index in range(parent_count):
        name = f"Parent {index}"
        event_names = (
            frozenset({"pull_request"})
            if index == parent_count - 1
            else frozenset({"workflow_run"})
        )
        parents = () if index == parent_count - 1 else (f"Parent {index + 1}",)
        workflow = WorkflowSummary(
            filepath=f"{index:04}.yml",
            content="",
            lines=[],
            raw_event_names=event_names,
            workflow_name=name,
            workflow_run_parents=parents,
        )
        workflows[workflow.filepath] = workflow
    child = WorkflowSummary(
        filepath="child.yml",
        content="",
        lines=[],
        raw_event_names=frozenset({"workflow_run"}),
        workflow_name="Child",
        workflow_run_parents=("Parent 0",),
    )
    workflows[child.filepath] = child
    corpus = WorkflowCorpus(repo_path="synthetic", workflows=workflows)

    assert corpus.workflow_run_parent_fork_reachable(child) is None
    assert corpus.has_external_privileged_trigger(child) is True


def test_pull_request_with_custom_pat_keeps_checkout_finding_but_not_github_token_chain(
    tmp_path: Path,
) -> None:
    pat_reference = "$" + "{{ secrets.STATUS_PAT }}"
    checkout = (
        "      - uses: actions/checkout@v4\n        with:\n          token: " + pat_reference + "\n"
    )
    _write_workflow(
        tmp_path,
        "ci.yml",
        _workflow(" pull_request", checkout=checkout),
    )
    assert _findings(tmp_path, "SEC4-GH-005")
    assert _findings(tmp_path, "CHAIN-GH-101") == []


def test_persist_credentials_false_keeps_chain_clean(tmp_path: Path) -> None:
    checkout = (
        "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    )
    _write_workflow(
        tmp_path,
        "ci.yml",
        _workflow(" pull_request_target", checkout=checkout),
    )
    assert _findings(tmp_path, "CHAIN-GH-101") == []


def test_read_only_job_keeps_chain_clean(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        _workflow(" pull_request_target", job_permissions="read"),
    )
    assert _findings(tmp_path, "CHAIN-GH-101") == []


def test_trusted_actor_does_not_prove_checkout_or_credential_integrity(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        _workflow(
            " pull_request_target",
            job_if="github.actor == 'dependabot[bot]'",
        ),
    )
    candidates = _findings(tmp_path, "CHAIN-GH-101")
    assert candidates
    assert all(f.review_needed for f in candidates)
    assert all("not proven" in f.snippet for f in candidates)
