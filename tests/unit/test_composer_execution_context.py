"""Execution context belongs to the actual job and step that contain a finding."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.agentguards import AgentGuardIndex
from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _workflow(path: Path, body: str, name: str = "context.yml") -> Path:
    target = path / ".github" / "workflows" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return target


def _findings(path: Path):
    reports = scan_repo(str(path), load_all_rules(), Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return findings


def _ids(findings):
    return {finding.rule_id for finding in findings}


def _taint_workflow(
    *,
    job_if: str = "",
    step_if: str = "",
    extra_steps: str = "",
    on_block: str = "on: [push, pull_request_target]",
) -> str:
    job_guard = f"    if: {job_if}\n" if job_if else ""
    step_guard = f"        if: {step_if}\n" if step_if else ""
    return (
        "name: execution context\n" + on_block + "\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n" + job_guard + "    steps:\n"
        "      - name: execute title\n"
        "        env:\n"
        "          VALUE: ${{ github.event.pull_request.title }}\n"
        + step_guard
        + '        run: eval "$VALUE"\n'
        + extra_steps
    )


@pytest.mark.parametrize(
    "guard",
    [
        "github.actor == 'dependabot[bot]'",
        "github.actor == 'dependabot[bot]' || github.actor != 'dependabot[bot]'",
        "\"! (github.actor == 'dependabot[bot]')\"",
    ],
)
def test_unrelated_bot_guard_does_not_suppress_external_taint_chain(tmp_path, guard):
    body = _taint_workflow(
        extra_steps=(
            "      - name: unrelated guard\n"
            "        if: " + guard + "\n"
            "        run: echo maintenance\n"
        )
    )
    _workflow(tmp_path, body)
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert "CHAIN-GH-103" in _ids(findings)


def test_exact_bot_job_guard_does_not_prove_external_input_integrity(tmp_path):
    _workflow(
        tmp_path,
        _taint_workflow(job_if="github.actor == 'dependabot[bot]'"),
    )
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert "CHAIN-GH-103" in _ids(findings)


@pytest.mark.parametrize(
    ("job_if", "step_if"),
    [
        ("github.event_name == 'push'", ""),
        ("", "github.event_name == 'push'"),
        ("github.event_name == 'push'", "github.event_name == 'push'"),
        ("\"github.event_name == 'push'\"", ""),
        (">-\n      github.event_name == 'push'", ""),
    ],
)
def test_proven_push_only_owner_guards_remove_pr_chain(tmp_path, job_if, step_if):
    _workflow(tmp_path, _taint_workflow(job_if=job_if, step_if=step_if))
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert "CHAIN-GH-103" not in _ids(findings)


@pytest.mark.parametrize(
    "job_if",
    [
        "github.event_name == inputs.event",
        "[github.event_name == 'push']",
        "github.event_name == 'push'",  # duplicate key below makes ownership ambiguous
    ],
)
def test_unknown_or_ambiguous_owner_guards_retain_chain_candidate(tmp_path, job_if):
    body = _taint_workflow(job_if=job_if)
    if job_if == "github.event_name == 'push'":
        body = body.replace(
            "    if: github.event_name == 'push'\n",
            "    if: github.event_name == 'push'\n"
            "    if: github.event_name == 'pull_request_target'\n",
            1,
        )
    _workflow(tmp_path, body)
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert "CHAIN-GH-103" in _ids(findings)


def test_malformed_owner_guard_retains_chain_candidate(tmp_path):
    _workflow(
        tmp_path,
        _taint_workflow(job_if="${{ github.event_name == 'push'"),
    )
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert "CHAIN-GH-103" in _ids(findings)


@pytest.mark.parametrize(
    ("on_block", "expected_taint"),
    [
        ("on: pull_request_target", False),
        ("on: [push, pull_request_target]", True),
        ("on:\n  - push\n  - pull_request_target", True),
        ("on: {push: {}, pull_request_target: {}}", True),
    ],
)
def test_supported_trigger_shapes_honor_owning_push_only_job_guard(
    tmp_path, on_block, expected_taint
):
    _workflow(
        tmp_path,
        _taint_workflow(job_if="github.event_name == 'push'", on_block=on_block),
    )
    findings = _findings(tmp_path)
    assert ("TAINT-GH-001" in _ids(findings)) is expected_taint
    assert "CHAIN-GH-103" not in _ids(findings)


@pytest.mark.parametrize(
    "content",
    [
        "jobs:\n  build:\n    if: github.event_name == 'push'\n",  # missing on
        "on: [push, pull_request_target, custom_event]\n",  # unknown event
        "on: pull_request_target\n  push:\n",  # scalar with malformed child
        "on: {pull_request_target: {}}\n  push:\n",  # flow map with malformed child
        "on: {pull_request_target: {}} push\n",  # trailing flow-map content
        "on:\n  pull_request_target:\n  {}\n",  # block map with malformed child
        "on:\n  pull_request_target: {} push\n",  # block peer with trailing flow text
        "on:\n  pull_request_target: {}\n  {}\n",  # malformed peer mapping
        "on:\n  pull_request_target: {}\n    []\n",  # malformed nested sequence
        "on: [push, pull_request_target]\non: [push]\n",  # duplicate on
        "on: &events [push, pull_request_target]\n",  # alias/anchor
        "on: [push, pull_request_target]\n---\non: [push]\n",  # multi-document
    ],
)
def test_incomplete_trigger_declarations_cannot_certify_event_pruning(content):
    from taintly.composer import _certified_composer_events

    assert _certified_composer_events(content) is None


def test_guard_index_resolves_structural_owner_and_unknown_stays_unknown():
    content = (
        "on: [push, pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    if: github.event_name == 'push'\n"
        "    steps:\n"
        "      - run: echo ok\n"
    )
    index = AgentGuardIndex(content)
    owner = index.owner(6)
    assert owner == ("jobs", "build", "steps", 0)
    assert index.excludes(owner) is True
    assert index.excludes(("jobs", "missing", "steps", 0)) is False


def test_guard_indexes_are_source_bound_and_aliases_remain_unknown():
    guarded = AgentGuardIndex(
        "on: [push, pull_request_target]\n"
        "jobs:\n  build:\n    if: github.event_name == 'push'\n"
        "    steps:\n      - run: echo guarded\n"
    )
    unguarded = AgentGuardIndex(
        "on: [push, pull_request_target]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo unguarded\n"
    )
    owner = ("jobs", "build", "steps", 0)
    assert guarded.excludes(owner) is True
    assert unguarded.excludes(owner) is False

    merged = AgentGuardIndex(
        "on: [push, pull_request_target]\n"
        "jobs:\n  defaults: &job\n    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        "  build:\n    <<: *job\n"
    )
    assert merged.valid is False
    assert merged.excludes(owner) is False


def _crossjob_workflow(*, producer_if: str = "", consumer_if: str = "", sibling: str = "") -> str:
    producer_guard = f"    if: {producer_if}\n" if producer_if else ""
    consumer_guard = f"    if: {consumer_if}\n" if consumer_if else ""
    return (
        "on: [pull_request_target, issues]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n" + producer_guard + "    outputs:\n"
        "      val: ${{ steps.source.outputs.val }}\n"
        "    steps:\n"
        "      - id: source\n"
        '        run: echo "val=hello" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n" + consumer_guard + "    steps:\n"
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n' + sibling
    )


def _crossjob_job_env_workflow(
    *,
    producer_if: str = "",
    consumer_if: str = "",
    reader_if: str = "",
    authority_if: str = "",
    separate_reader: bool = False,
) -> str:
    producer_guard = f"    if: {producer_if}\n" if producer_if else ""
    consumer_guard = f"    if: {consumer_if}\n" if consumer_if else ""
    reader_guard = f"        if: {reader_if}\n" if reader_if else ""
    authority_guard = f"        if: {authority_if}\n" if authority_if else ""
    reader = (
        "      - name: consume transferred value\n" + reader_guard + '        run: echo "$VALUE"\n'
        if separate_reader
        else ""
    )
    authority_value = (
        'gh issue edit 1 --add-label "constant"'
        if separate_reader
        else 'gh issue edit 1 --add-label "$VALUE"'
    )
    return (
        "on: [issues, pull_request_target, push]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n" + producer_guard + "    outputs:\n"
        "      val: ${{ steps.source.outputs.val }}\n"
        "    steps:\n"
        "      - id: source\n"
        '        run: echo "val=hello" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n" + consumer_guard + "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        + reader
        + "      - name: use write authority\n"
        + authority_guard
        + f"        run: {authority_value}\n"
    )


def _crossjob_step_local_workflow(*, producer_if: str, reader_if: str) -> str:
    return (
        "on: [issues, pull_request_target]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        f"    if: {producer_if}\n"
        "    outputs:\n"
        "      val: ${{ steps.source.outputs.val }}\n"
        "    steps:\n"
        "      - id: source\n"
        '        run: echo "val=hello" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - name: read and exercise authority\n"
        f"        if: {reader_if}\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n"
        '        run: gh issue edit 1 --add-label "$VALUE"\n'
    )


def test_crossjob_chain_requires_compatible_same_external_event_guards(tmp_path):
    _workflow(
        tmp_path,
        _crossjob_workflow(
            producer_if="github.event_name == 'issues'",
            consumer_if="github.event_name == 'pull_request_target'",
        ),
    )
    findings = _findings(tmp_path)
    assert "CHAIN-GH-105" not in _ids(findings)


def test_crossjob_chain_can_use_a_shared_external_privileged_event(tmp_path):
    _workflow(
        tmp_path,
        _crossjob_workflow(
            producer_if="github.event_name == 'issues'",
            consumer_if="github.event_name == 'issues'",
        ),
    )
    findings = _findings(tmp_path)
    assert "CHAIN-GH-105" in _ids(findings)


@pytest.mark.parametrize(
    ("authority_if", "expected"),
    [
        ("github.event_name == 'push'", False),
        ("github.event_name == 'issues'", True),
        ("github.actor == 'somebody'", True),
    ],
)
def test_job_env_output_requires_compatible_authority_step_event(tmp_path, authority_if, expected):
    _workflow(
        tmp_path,
        _crossjob_job_env_workflow(
            producer_if="github.event_name == 'issues'",
            authority_if=authority_if,
        ),
    )
    findings = _findings(tmp_path)
    assert ("CHAIN-GH-105" in _ids(findings)) is expected


def test_job_env_reference_with_separate_guarded_reader_remains_qualified_review(tmp_path):
    _workflow(
        tmp_path,
        _crossjob_job_env_workflow(
            producer_if="github.event_name == 'issues'",
            reader_if="github.event_name == 'pull_request_target'",
            authority_if="github.event_name == 'issues'",
            separate_reader=True,
        ),
    )
    findings = _findings(tmp_path)
    chain = next(finding for finding in findings if finding.rule_id == "CHAIN-GH-105")
    # The job-level env binding is in scope for the authority step. An
    # unrelated guarded echo cannot prove that it is the only reader.
    assert chain.review_needed
    assert "does not establish a successful privilege escalation" in chain.snippet


def test_step_local_needs_reference_guarded_to_disjoint_event_is_not_chained(tmp_path):
    _workflow(
        tmp_path,
        _crossjob_step_local_workflow(
            producer_if="github.event_name == 'issues'",
            reader_if="github.event_name == 'pull_request_target'",
        ),
    )
    findings = _findings(tmp_path)
    assert "CHAIN-GH-105" not in _ids(findings)


@pytest.mark.parametrize(
    "extra",
    ["[]\n", "push:\n", "- true\n"],
)
def test_malformed_scalar_job_guard_cannot_prove_exclusion(tmp_path, extra):
    from taintly.composer import Database, _seed_execution_contexts, execution_events_for
    from taintly.workflow_corpus import build_corpus

    body = _taint_workflow(job_if="false")
    body = body.replace("    if: false\n", "    if: false\n      " + extra, 1)
    path = _workflow(tmp_path, body)
    db = Database()
    _seed_execution_contexts(db, build_corpus(str(tmp_path)))
    assert execution_events_for(db, str(path), "build") is None


def test_guarded_sibling_job_does_not_suppress_compatible_crossjob_chain(tmp_path):
    sibling = (
        "  maintenance:\n"
        "    runs-on: ubuntu-latest\n"
        "    if: github.actor == 'dependabot[bot]'\n"
        "    steps:\n"
        "      - run: echo maintenance\n"
    )
    _workflow(tmp_path, _crossjob_workflow(sibling=sibling))
    findings = _findings(tmp_path)
    assert "CHAIN-GH-105" in _ids(findings)


def test_identically_named_jobs_in_different_files_keep_local_context(tmp_path):
    guarded = _workflow(
        tmp_path,
        _taint_workflow(job_if="github.event_name == 'push'"),
        name="guarded.yml",
    )
    live = _workflow(tmp_path, _taint_workflow(), name="live.yml")
    findings = _findings(tmp_path)
    chains = [finding for finding in findings if finding.rule_id == "CHAIN-GH-103"]
    assert [finding.file for finding in chains] == [str(live)]
    assert str(guarded) not in {finding.file for finding in chains}


@pytest.mark.parametrize(
    ("parents", "parent_workflows", "expected_chain"),
    [
        (["Push Parent"], [("Push Parent", "push")], False),
        (["Missing Parent"], [], True),
        (
            ["Push Parent", "External Parent"],
            [("Push Parent", "push"), ("External Parent", "issues")],
            True,
        ),
    ],
)
def test_workflow_run_parent_context_preserves_known_unknown_and_mixed_cases(
    tmp_path, parents, parent_workflows, expected_chain
):
    parent_list = ", ".join(f"'{name}'" for name in parents)
    child = (
        "name: downstream\n"
        "on:\n"
        "  workflow_run:\n"
        f"    workflows: [{parent_list}]\n"
        "    types: [completed]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          VALUE: ${{ github.event.workflow_run.head_branch }}\n"
        '        run: eval "$VALUE"\n'
    )
    _workflow(tmp_path, child, name="downstream.yml")
    for index, (name, event) in enumerate(parent_workflows):
        parent = (
            f"name: {name}\n"
            f"on: {event}\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo parent\n"
        )
        _workflow(tmp_path, parent, name=f"parent-{index}.yml")
    findings = _findings(tmp_path)
    assert "TAINT-GH-001" in _ids(findings)
    assert ("CHAIN-GH-103" in _ids(findings)) is expected_chain


def test_chain_102_103_104_remain_review_needed_and_do_not_claim_secret_absence(tmp_path):
    body = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: example/deploy-action@v1\n"
        "        with:\n"
        "          token: ${{ secrets.DEPLOY_TOKEN }}\n"
        "      - uses: example/collect@v1\n"
        "        with:\n"
        "          token: ${{ secrets.DEPLOY_TOKEN }}\n"
        "      - env:\n"
        "          VALUE: ${{ github.event.pull_request.title }}\n"
        '        run: eval "$VALUE"\n'
    )
    _workflow(tmp_path, body)
    findings = _findings(tmp_path)
    chains = [
        finding
        for finding in findings
        if finding.rule_id in {"CHAIN-GH-102", "CHAIN-GH-103", "CHAIN-GH-104"}
    ]
    assert {finding.rule_id for finding in chains} >= {"CHAIN-GH-102", "CHAIN-GH-104"}
    assert all(finding.review_needed for finding in chains)
    assert all(
        "secrets are unavailable" not in finding.snippet.lower()
        and "environment isolation prevents" not in finding.snippet.lower()
        for finding in chains
    )
