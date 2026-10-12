"""Event compatibility for LOTP PR-source checkout/build paths.

These tests keep event availability separate from the spelling of a source:
``github.head_ref`` only identifies PR-head data on pull_request events, while
literal ``refs/pull/N/{head,merge}`` refs remain PR source even on push.
Only a valid, recognized top-level trigger declaration can certify source
unavailability; absent, ambiguous, malformed, nested, or multi-document
markers stay conservative.
"""

from __future__ import annotations

import pytest

from taintly.rules.registry import get_rule_by_id


RULE_IDS = ("LOTP-GH-001", "LOTP-GH-003")


def _source_workflow(
    trigger: str | None,
    checkout_ref: str,
    *,
    build_if: str | None = None,
    checkout_path: str | None = None,
    build_directory: str | None = None,
    build_tool: str = "npm install",
    extra_steps: str = "",
) -> str:
    trigger_block = "" if trigger is None else trigger.rstrip() + "\n"
    path_input = f"          path: {checkout_path}\n" if checkout_path else ""
    return (
        trigger_block
        + "jobs:\n"
        + "  build:\n"
        + "    runs-on: ubuntu-latest\n"
        + "    steps:\n"
        + "      - uses: actions/checkout@v4\n"
        + "        with:\n"
        + f"          ref: {checkout_ref}\n"
        + path_input
        + extra_steps
        + "      - run: echo prepare\n"
        + "      - "
        + (f"if: {build_if}\n        " if build_if else "")
        + f"run: {build_tool}\n"
        + (f"        working-directory: {build_directory}\n" if build_directory else "")
    )


def _matches(body: str, rule_id: str = "LOTP-GH-001") -> list[tuple[int, str]]:
    rule = get_rule_by_id(rule_id)
    assert rule is not None
    return rule.pattern.check(body, body.splitlines())


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_head_ref_is_not_a_pr_source_on_push_and_manual_dispatch(rule_id: str) -> None:
    body = _source_workflow(
        "on:\n  push: {}\n  workflow_dispatch: {}",
        "${{ github.head_ref }}",
    )
    assert not _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_exact_head_ref_remains_pr_source_on_pull_request_target(rule_id: str) -> None:
    body = _source_workflow(
        "on:\n  pull_request_target: {}",
        "${{ github.head_ref }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("pr_ref", ["refs/pull/42/head", "pull/42/merge"])
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_literal_pull_request_refs_match_on_push(pr_ref: str, rule_id: str) -> None:
    body = _source_workflow("on: push", pr_ref)
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_checkout_repository_does_not_make_push_head_ref_available(rule_id: str) -> None:
    body = _source_workflow(
        "on: [push, workflow_dispatch]",
        "${{ github.head_ref }}",
    ).replace(
        "          ref: ${{ github.head_ref }}\n",
        "          repository: ${{ github.repository }}\n          ref: ${{ github.head_ref }}\n",
    )
    assert not _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_git_checkout_literal_pr_ref_survives_push_guard(rule_id: str) -> None:
    body = _source_workflow(
        "on: push",
        "main",
        build_if="${{ github.event_name == 'push' }}",
        extra_steps="      - run: git checkout refs/pull/42/head\n",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_gh_pr_checkout_survives_push_guard(rule_id: str) -> None:
    body = _source_workflow(
        "on: push",
        "main",
        build_if="${{ github.event_name == 'push' }}",
        extra_steps="      - run: gh pr checkout 42\n",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_separate_literal_pr_source_survives_unavailable_head_ref(rule_id: str) -> None:
    body = _source_workflow(
        "on: push",
        "${{ github.head_ref }}",
        extra_steps="      - run: git checkout pull/42/merge\n",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("pr_ref", ["refs/pull/42/head", "pull/42/merge"])
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_push_guard_does_not_suppress_literal_pull_request_source(
    pr_ref: str, rule_id: str
) -> None:
    body = _source_workflow(
        "on: push",
        pr_ref,
        build_if="${{ github.event_name == 'push' }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_workflow_run_head_branch_with_matching_guard_remains_a_source(rule_id: str) -> None:
    body = _source_workflow(
        "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]",
        "${{ github.event.workflow_run.head_branch }}",
        build_if="${{ github.event_name == 'workflow_run' }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_pr_only_head_ref_with_push_guard_stays_suppressed(rule_id: str) -> None:
    body = _source_workflow(
        "on: [pull_request, push]",
        "${{ github.head_ref }}",
        build_if="${{ github.event_name == 'push' }}",
    )
    assert not _matches(body, rule_id)


@pytest.mark.parametrize(
    "reference",
    ["${{ github['head_ref'] }}", "${{ GITHUB.HEAD_REF }}"],
)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_bracket_and_case_variants_follow_head_ref_event_availability(
    reference: str, rule_id: str
) -> None:
    push_dispatch = _source_workflow("on: [push, workflow_dispatch]", reference)
    pull_request = _source_workflow("on: pull_request", reference)
    assert not _matches(push_dispatch, rule_id)
    assert _matches(pull_request, rule_id)


@pytest.mark.parametrize("trigger", [None, "on: null", "on: {}", "on: []"])
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_missing_null_or_empty_trigger_remains_conservative(
    trigger: str | None, rule_id: str
) -> None:
    assert _matches(_source_workflow(trigger, "${{ github.head_ref }}"), rule_id)


@pytest.mark.parametrize(
    "trigger",
    [
        "on: push\non: workflow_dispatch",
        "on: workflow_dispatch\non: push",
        "on: push\non: pull_request_target",
        "on: pull_request_target\non: push",
        "events: &events [push, workflow_dispatch]\non: *events",
        "events: &events\n  push: {}\n  workflow_dispatch: {}\non:\n  <<: *events",
        "on:\n  push: [\n",
        "on: [push, {}]",
        "on: [push, []]",
        "on: [push, ,]",
        "on: {push: pull_request}",
        "on: {push: []}",
        "on:\n  invented_event: {}",
        "on: workflow_call",
    ],
)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_ambiguous_or_unrecognized_trigger_remains_conservative(trigger: str, rule_id: str) -> None:
    assert _matches(_source_workflow(trigger, "${{ github.head_ref }}"), rule_id)


@pytest.mark.parametrize(
    "trigger",
    [
        "on: push",
        "on: workflow_dispatch",
        "on: [push, workflow_dispatch]",
        "on: {push: {}, workflow_dispatch: {}}",
        "on:\n  - push\n  - workflow_dispatch",
        "'on':\n  push: {}\n  workflow_dispatch: {}",
        "on: # event list\n  push: {}\n  workflow_dispatch: {}",
    ],
)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_supported_push_and_manual_trigger_forms_suppress_exact_head_ref(
    trigger: str, rule_id: str
) -> None:
    assert not _matches(_source_workflow(trigger, "${{ github.head_ref }}"), rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_compound_head_ref_fallback_remains_conservative_on_push(rule_id: str) -> None:
    body = _source_workflow(
        "on: [push, workflow_dispatch]",
        "${{ github.head_ref || github.ref }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize(
    "reference",
    [
        "${{ github.head_ref || 'refs/pull/42/head' }}",
        "${{ github.head_ref || inputs.ref }}",
    ],
)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_compound_head_ref_fallback_with_push_guard_remains_conservative(
    reference: str, rule_id: str
) -> None:
    body = _source_workflow(
        "on: push",
        reference,
        build_if="${{ github.event_name == 'push' }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_independent_unknown_checkout_after_head_ref_stays_conservative(
    rule_id: str,
) -> None:
    body = _source_workflow(
        "on: push",
        "main",
        build_if="${{ github.event_name == 'push' }}",
        extra_steps=("      - run: git checkout '${{ github.head_ref }}'; git checkout \"$REF\"\n"),
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_compound_event_guard_does_not_exclude_pr_source_path(rule_id: str) -> None:
    body = _source_workflow(
        "on: [push, pull_request]",
        "${{ github.head_ref }}",
        build_if="${{ github.event_name == 'push' || github.event_name == 'pull_request' }}",
    )
    assert _matches(body, rule_id)


@pytest.mark.parametrize(
    "body",
    [
        # `on` nested in job data is not a workflow trigger declaration.
        "jobs:\n  build:\n    env:\n      on:\n        push: true\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
        "      - run: npm install\n",
        # Trigger-like text in a command does not declare an event.
        "jobs:\n  build:\n    steps:\n"
        "      - run: echo 'on: push'\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
        "      - run: npm install\n",
        # The trigger and job are in separate YAML documents; a document
        # marker prevents them from jointly certifying one workflow.
        "---\non: push\n...\n---\n"
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
        "      - run: npm install\n",
        # Malformed trigger syntax cannot prove source unavailability.
        "on: {push: \n"
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
        "      - run: npm install\n",
    ],
)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_nested_script_marker_multidoc_or_malformed_trigger_stays_unknown(
    body: str, rule_id: str
) -> None:
    assert _matches(body, rule_id)


def test_static_base_checkout_remains_trusted() -> None:
    body = _source_workflow("on: pull_request", "main")
    assert not _matches(body)


def test_fixed_branch_switch_after_pr_source_remains_trusted() -> None:
    body = _source_workflow(
        "on: pull_request",
        "${{ github.head_ref }}",
        extra_steps="      - run: git switch main\n",
    )
    assert not _matches(body)


def test_build_before_pr_checkout_does_not_match() -> None:
    body = (
        "on: pull_request\n"
        "jobs:\n  build:\n    steps:\n"
        "      - run: npm install\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
    )
    assert not _matches(body)


def test_checkout_path_does_not_supply_source_for_build_in_another_directory() -> None:
    body = _source_workflow(
        "on: pull_request",
        "${{ github.head_ref }}",
        checkout_path="src",
        build_directory="docs",
    )
    assert not _matches(body)
