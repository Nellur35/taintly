"""Structural-reader contracts for scalar YAML aliases."""

from __future__ import annotations

import pytest

from taintly.parsers.structural import EventKind, walk_workflow
from taintly.parsers.structural import walker as structural_walker
from taintly.parsers.structural.tokenizer import TokenizerError


@pytest.mark.parametrize(
    "anchor_value",
    ["main", '"main"', "'main'"],
)
def test_scalar_alias_replays_at_exact_destination_and_alias_line(anchor_value: str) -> None:
    source = f"value: &branch {anchor_value}\ncheckout_ref: *branch\n"

    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR
    ]

    assert [(event.path, event.value, event.line) for event in leaves] == [
        (("value",), "main", 1),
        (("checkout_ref",), "main", 2),
    ]


def test_scalar_alias_capture_does_not_absorb_next_sibling() -> None:
    source = (
        "env:\n"
        '  PR_HEAD: &pr_head "${{ github.event.pull_request.head.sha }}"\n'
        "  SAFE_REF: main\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: *pr_head\n"
    )

    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR
    ]
    by_path = {event.path: event for event in leaves}

    assert by_path[("env", "SAFE_REF")].value == "main"
    assert by_path[("jobs", "build", "steps", 0, "with", "ref")].value == (
        "${{ github.event.pull_request.head.sha }}"
    )
    assert by_path[("jobs", "build", "steps", 0, "with", "ref")].line == 9


def test_sequence_alias_replay_keeps_indices_and_alias_line() -> None:
    source = ".commands: &commands\n  - echo one\n  - echo two\nscript: *commands\n"

    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR
    ]

    assert [(event.path, event.value, event.line) for event in leaves[-2:]] == [
        (("script", 0), "echo one", 4),
        (("script", 1), "echo two", 4),
    ]


def test_mapping_and_nested_merge_aliases_remain_unchanged() -> None:
    source = (
        "defaults: &defaults\n  with: &inputs\n    ref: main\njobs:\n  build:\n    <<: *defaults\n"
    )

    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR
    ]

    assert any(
        event.path == ("jobs", "build", "with", "ref") and event.value == "main" and event.line == 6
        for event in leaves
    )


def test_scalar_anchor_cannot_be_used_as_mapping_merge() -> None:
    source = "defaults: &defaults main\njobs:\n  build:\n    <<: *defaults\n"

    events = list(walk_workflow("workflow.yml", content=source, recover=True))

    assert any(
        event.kind is EventKind.ERROR
        and event.line == 4
        and "must reference a mapping, not scalar" in (event.message or "")
        for event in events
    )
    assert not any(
        event.kind is EventKind.LEAF_SCALAR
        and event.path == ("jobs", "build")
        and event.value == "main"
        for event in events
    )


def test_nested_alias_replay_is_captured_by_enclosing_mapping_anchor() -> None:
    source = (
        'pr_head: &pr_head "${{ github.event.pull_request.head.sha }}"\n'
        "jobs:\n"
        "  build:\n"
        "    env: &checkout_inputs\n"
        "      ref: *pr_head\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with: *checkout_inputs\n"
    )

    leaves = [
        event
        for event in walk_workflow("workflow.yml", content=source)
        if event.kind is EventKind.LEAF_SCALAR
    ]

    replayed_ref = next(
        event for event in leaves if event.path == ("jobs", "build", "steps", 0, "with", "ref")
    )
    assert replayed_ref.value == "${{ github.event.pull_request.head.sha }}"
    assert replayed_ref.line == 8


def test_recursive_alias_stops_with_cutoff_and_strict_error() -> None:
    source = "node: &node\n  next: *node\nafter: visible\n"

    events = list(walk_workflow("workflow.yml", content=source, recover=True))

    cutoffs = [event for event in events if event.kind is EventKind.CUTOFF]
    assert len(cutoffs) == 1
    assert cutoffs[0].line == 2
    assert not any(event.path == ("after",) for event in events)
    with pytest.raises(TokenizerError, match="recursive anchor alias"):
        list(walk_workflow("workflow.yml", content=source, recover=False))


def test_nested_alias_expansion_uses_shared_fuel_and_stops_tail(monkeypatch) -> None:
    monkeypatch.setattr(structural_walker, "MAX_ANCHOR_WORK", 22)
    source = (
        "base: &base\n"
        "  value: x\n"
        "wrapper: &wrapper\n"
        "  first: *base\n"
        "  second: *base\n"
        "copy: *wrapper\n"
        "after: visible\n"
    )

    events = list(walk_workflow("workflow.yml", content=source, recover=True))

    cutoffs = [event for event in events if event.kind is EventKind.CUTOFF]
    assert len(cutoffs) == 1
    assert cutoffs[0].line == 6
    assert not any(event.path == ("after",) for event in events)


def test_repeated_aliases_share_fuel_outside_active_captures(monkeypatch) -> None:
    monkeypatch.setattr(structural_walker, "MAX_ANCHOR_WORK", 8)
    source = (
        "template: &template\n"
        "  value: x\n"
        "copy_one: *template\n"
        "copy_two: *template\n"
        "after: visible\n"
    )

    events = list(walk_workflow("workflow.yml", content=source, recover=True))

    cutoffs = [event for event in events if event.kind is EventKind.CUTOFF]
    assert len(cutoffs) == 1
    assert cutoffs[0].line == 4
    assert not any(event.path == ("after",) for event in events)
