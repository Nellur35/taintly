"""Unit tests for the structural ``triggers()`` query + the opt-in MAP_KEY
walker event it relies on.

Covers the exact encodings that motivated the migration: the flow-mapping and
empty-block-value forms that emit no LEAF_SCALAR, and the block-list form the
legacy regex (`workflow_corpus._extract_raw_events`) silently drops.
"""

from __future__ import annotations

import pytest

from taintly.parsers.structural import EventKind, triggers, walk_workflow

_JOBS = "\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"


@pytest.mark.parametrize(
    ("name", "on_block", "expected"),
    [
        ("bare", "on: pull_request_target", {"pull_request_target"}),
        ("flow-list", "on: [push, pull_request_target]", {"push", "pull_request_target"}),
        ("block-list", "on:\n  - push\n  - pull_request_target", {"push", "pull_request_target"}),
        ("block-map-empty", "on:\n  pull_request_target:", {"pull_request_target"}),
        (
            "block-map-config",
            "on:\n  push:\n    branches: [main]\n  pull_request_target:",
            {"push", "pull_request_target"},
        ),
        ("flow-map", "on: { pull_request_target: {} }", {"pull_request_target"}),
        (
            "flow-map-config",
            "on: { pull_request_target: { types: [opened] }, push: {} }",
            {"pull_request_target", "push"},
        ),
    ],
)
def test_triggers_all_on_encodings(name: str, on_block: str, expected: set) -> None:
    assert triggers(on_block + _JOBS) == expected


def test_triggers_fixes_block_list_regex_blind_spot() -> None:
    """The legacy regex `_extract_raw_events` skips block-sequence dashes and
    so returns nothing for the block-list form; triggers() reads it correctly.
    This documents the structural recall win (and guards against regression)."""
    from taintly.workflow_corpus import _extract_raw_events

    content = "on:\n  - push\n  - pull_request_target" + _JOBS
    assert triggers(content) == {"push", "pull_request_target"}
    # The bug being fixed: the regex helper sees no events here.
    assert _extract_raw_events(content) == set()


def test_map_key_is_opt_in_off_by_default() -> None:
    """Default walk must emit NO MAP_KEY events (byte-identical event stream
    for existing leaf-only consumers)."""
    content = "on:\n  pull_request_target:" + _JOBS
    default = [ev for ev in walk_workflow("w.yml", content=content)]
    assert all(ev.kind is not EventKind.MAP_KEY for ev in default)


def test_map_key_emitted_when_requested() -> None:
    content = "on:\n  pull_request_target:" + _JOBS
    keys = [
        ev.path
        for ev in walk_workflow("w.yml", content=content, include_keys=True)
        if ev.kind is EventKind.MAP_KEY
    ]
    assert ("on", "pull_request_target") in keys


def test_triggers_empty_when_no_on_block() -> None:
    assert triggers("jobs:\n  build:\n    steps:\n      - run: echo hi\n") == frozenset()
