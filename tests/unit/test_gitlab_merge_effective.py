"""Contracts for effective GitLab YAML merge-key precedence.

The structural reader can replay anchors, but only GitLab consumers should
apply GitLab's explicit-over-merged-key rules. These tests exercise the
resolver, the single-file taint analyzer, and the opt-in effective view.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from taintly.engine import scan_repo
from taintly.gitlab_inherit import find_cross_file_taint, resolve_pipeline
from taintly.gitlab_taint import analyze
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _taint_paths(content: str):
    return analyze(content, content.splitlines())


def _cross_file_paths(content: str):
    return find_cross_file_taint([(".gitlab-ci.yml", content)])


def _effective_events(content: str):
    from taintly._gitlab_effective import walk_gitlab_effective

    return walk_gitlab_effective(".gitlab-ci.yml", content=content)


def _engine_findings(tmp_path, rule_id: str):
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITLAB)
    return [
        finding for report in reports for finding in report.findings if finding.rule_id == rule_id
    ]


def _values(events: Iterable[object], path: tuple[object, ...]) -> list[str]:
    return [
        event.value for event in events if event.kind.value == "leaf_scalar" and event.path == path
    ]


@pytest.mark.parametrize(
    "merge_first", [True, False], ids=["merge-before-explicit", "explicit-before-merge"]
)
@pytest.mark.parametrize(
    ("anchor_value", "explicit_value", "expected_value", "expected_flow"),
    [
        ("$CI_COMMIT_TITLE", "safe", "safe", False),
        ("safe", "$CI_COMMIT_TITLE", "$CI_COMMIT_TITLE", True),
    ],
    ids=["explicit-safe-wins", "explicit-taint-wins"],
)
def test_taint_gl_001_uses_effective_explicit_variable_override(
    merge_first: bool,
    anchor_value: str,
    explicit_value: str,
    expected_value: str,
    expected_flow: bool,
) -> None:
    merge_line = "    <<: *defaults\n"
    explicit_lines = f"    CMD: {explicit_value}\n"
    variables = merge_line + explicit_lines if merge_first else explicit_lines + merge_line
    content = (
        ".defaults: &defaults\n"
        f"  CMD: {anchor_value}\n"
        "build:\n"
        "  variables:\n" + variables + '  script:\n    - eval "$CMD"\n'
    )

    assert bool(_taint_paths(content)) is expected_flow
    effective = _effective_events(content)
    assert effective.complete
    assert _values(effective.events, ("build", "variables", "CMD")) == [expected_value]


@pytest.mark.parametrize(
    "merge_first", [True, False], ids=["merge-before-explicit", "explicit-before-merge"]
)
@pytest.mark.parametrize(
    ("anchor_value", "explicit_value", "expected_value", "expected_flow"),
    [
        ("$CI_COMMIT_TITLE", "safe", "safe", False),
        ("safe", "$CI_COMMIT_TITLE", "$CI_COMMIT_TITLE", True),
    ],
    ids=["explicit-safe-wins", "explicit-taint-wins"],
)
def test_taint_gl_008_uses_effective_explicit_override_through_extends(
    merge_first: bool,
    anchor_value: str,
    explicit_value: str,
    expected_value: str,
    expected_flow: bool,
) -> None:
    merge_line = "  <<: *defaults\n"
    explicit_lines = f"  variables:\n    CMD: {explicit_value}\n"
    template_body = merge_line + explicit_lines if merge_first else explicit_lines + merge_line
    content = (
        ".defaults: &defaults\n"
        "  variables:\n"
        f"    CMD: {anchor_value}\n"
        ".template:\n" + template_body + '  script:\n    - eval "$CMD"\n'
        "build:\n  extends: .template\n"
    )

    graph = resolve_pipeline([(".gitlab-ci.yml", content)])
    cmd = [leaf.value for leaf in graph.jobs["build"].leaves if leaf.path == ("variables", "CMD")]
    assert cmd == [expected_value]
    assert bool(_cross_file_paths(content)) is expected_flow


def test_inherited_tainted_anchor_without_override_still_fires() -> None:
    content = (
        ".defaults: &defaults\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        ".template:\n"
        "  <<: *defaults\n"
        '  script:\n    - eval "$CMD"\n'
        "build:\n  extends: .template\n"
    )

    flows = _cross_file_paths(content)
    assert [(flow.source_var, flow.laundered_var, flow.sink_kind) for flow in flows] == [
        ("CI_COMMIT_TITLE", "CMD", "script")
    ]


@pytest.mark.parametrize(
    "merge_first", [True, False], ids=["merge-before-explicit", "explicit-before-merge"]
)
@pytest.mark.parametrize(
    ("anchor_value", "explicit_value", "expected_finding"),
    [("$CI_COMMIT_TITLE", "safe", False), ("safe", "$CI_COMMIT_TITLE", True)],
    ids=["explicit-safe-wins", "explicit-taint-wins"],
)
def test_taint_gl_001_engine_finding_uses_effective_merge_precedence(
    tmp_path, merge_first: bool, anchor_value: str, explicit_value: str, expected_finding: bool
) -> None:
    merge_line = "    <<: *defaults\n"
    explicit_line = f"    CMD: {explicit_value}\n"
    variable_lines = merge_line + explicit_line if merge_first else explicit_line + merge_line
    content = (
        ".defaults: &defaults\n"
        f"  CMD: {anchor_value}\n"
        "build:\n  variables:\n" + variable_lines + '  script:\n    - eval "$CMD"\n'
    )
    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")

    assert bool(_engine_findings(tmp_path, "TAINT-GL-001")) is expected_finding


@pytest.mark.parametrize(
    "merge_first", [True, False], ids=["merge-before-explicit", "explicit-before-merge"]
)
@pytest.mark.parametrize(
    ("anchor_value", "explicit_value", "expected_finding"),
    [("$CI_COMMIT_TITLE", "safe", False), ("safe", "$CI_COMMIT_TITLE", True)],
    ids=["explicit-safe-wins", "explicit-taint-wins"],
)
def test_taint_gl_008_engine_finding_uses_effective_merge_precedence_across_include(
    tmp_path, merge_first: bool, anchor_value: str, explicit_value: str, expected_finding: bool
) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - local: templates.yml\nbuild:\n  extends: .template\n",
        encoding="utf-8",
    )
    merge_line = "  <<: *defaults\n"
    explicit_block = f"  variables:\n    CMD: {explicit_value}\n"
    template_body = merge_line + explicit_block if merge_first else explicit_block + merge_line
    (tmp_path / "templates.yml").write_text(
        ".defaults: &defaults\n"
        "  variables:\n"
        f"    CMD: {anchor_value}\n"
        ".template:\n" + template_body + '  script:\n    - eval "$CMD"\n',
        encoding="utf-8",
    )

    assert bool(_engine_findings(tmp_path, "TAINT-GL-008")) is expected_finding


@pytest.mark.parametrize(
    "replacement",
    ["{}", "[]", "null", "{CMD: safe}"],
    ids=["empty-map", "empty-list", "null", "replacement-map"],
)
def test_explicit_child_subtree_replacement_removes_merged_script(replacement: str) -> None:
    content = (
        ".defaults: &defaults\n"
        '  script:\n    - eval "$CMD"\n'
        "build:\n"
        "  <<: *defaults\n"
        f"  script: {replacement}\n"
    )

    effective = _effective_events(content)
    assert effective.complete
    assert _values(effective.events, ("build", "script", 0)) == []


def test_nested_variable_merge_overrides_only_the_named_child_and_keeps_sibling() -> None:
    content = (
        ".variables: &variables\n"
        "  CMD: $CI_COMMIT_TITLE\n"
        "  OTHER: $CI_COMMIT_BRANCH\n"
        "build:\n"
        "  variables:\n"
        "    <<: *variables\n"
        "    CMD: safe\n"
        '  script:\n    - eval "$CMD"\n    - echo "$OTHER"\n'
    )

    effective = _effective_events(content)
    assert effective.complete
    assert _values(effective.events, ("build", "variables", "CMD")) == ["safe"]
    assert _values(effective.events, ("build", "variables", "OTHER")) == ["$CI_COMMIT_BRANCH"]
    paths = _taint_paths(content)
    assert [(path.source_var, path.laundered_var, path.sink_line) for path in paths] == [
        ("CI_COMMIT_BRANCH", "OTHER", 10)
    ]


@pytest.mark.parametrize(
    ("anchor_value", "explicit_value", "expected_value", "expected_flow"),
    [
        ("$CI_COMMIT_TITLE", "safe", "safe", False),
        ("safe", "$CI_COMMIT_TITLE", "$CI_COMMIT_TITLE", True),
    ],
    ids=["explicit-safe-wins", "explicit-taint-wins"],
)
def test_nested_merge_bare_alias_then_outer_merge_keeps_precedence(
    anchor_value: str, explicit_value: str, expected_value: str, expected_flow: bool
) -> None:
    content = (
        f".base: &base\n  variables:\n    CMD: {anchor_value}\n"
        ".template: &template\n"
        "  <<: *base\n"
        "  variables:\n"
        "    <<: *base\n"
        f"    CMD: {explicit_value}\n"
        '  script:\n    - eval "$CMD"\n'
        ".carrier: &carrier\n"
        "  inner: *template\n"
        "build:\n"
        "  <<: *carrier\n"
        "  extends: .template\n"
    )

    effective = _effective_events(content)
    assert effective.complete
    assert _values(effective.events, ("build", "inner", "variables", "CMD")) == [expected_value]
    assert bool(_cross_file_paths(content)) is expected_flow


def test_default_structural_stream_stays_unannotated_and_opt_in_stream_tracks_merge_origins() -> (
    None
):
    from taintly.parsers.structural import walk_workflow

    content = ".base: &base\n  variables:\n    CMD: safe\nbuild:\n  <<: *base\n"
    default_events = tuple(walk_workflow(".gitlab-ci.yml", content=content))
    explicit_default_events = tuple(
        walk_workflow(".gitlab-ci.yml", content=content, include_merge_origins=False)
    )
    assert default_events == explicit_default_events
    assert all(event.merge_origins == () for event in default_events)

    annotated = tuple(walk_workflow(".gitlab-ci.yml", content=content, include_merge_origins=True))
    merged = next(event for event in annotated if event.path == ("build", "variables", "CMD"))
    assert merged.merge_origins
    assert merged.merge_origins[-1] == (("build",), "variables")


@pytest.mark.parametrize(
    ("suffix", "expected_flow", "expected_terminal"),
    [
        ("probe: *missing\n", True, "error"),
        ("%YAML 1.2\n", False, "cutoff"),
    ],
    ids=["recoverable-error", "cutoff"],
)
def test_effective_view_marks_error_or_cutoff_incomplete(
    suffix: str, expected_flow: bool, expected_terminal: str
) -> None:
    content = (
        ".base: &base\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        "build:\n"
        "  <<: *base\n"
        "  variables:\n"
        "    CMD: safe\n"
        '  script:\n    - eval "$CMD"\n' + suffix
    )
    effective = _effective_events(content)
    assert not effective.complete
    assert any(event.kind.value in {"error", "cutoff"} for event in effective.events)
    assert bool(_taint_paths(content)) is expected_flow
    assert effective.events[-1].kind.value == expected_terminal


@pytest.mark.parametrize(
    "ambiguity",
    [
        ".a: &a\n  variables:\n    CMD: safe\n"
        ".b: &b\n  variables:\n    CMD: $CI_COMMIT_TITLE\n"
        "build:\n  <<: *a\n  <<: *b\n",
        ".base: &base\n  variables:\n    CMD: safe\n"
        "build:\n  <<: *base\n  variables:\n    CMD: safe\n    CMD: $CI_COMMIT_TITLE\n",
        ".sequence: &sequence\n  - item\nbuild:\n  <<: *sequence\n",
        ".base: &base\n  variables:\n    CMD: $CI_COMMIT_TITLE\n"
        'build: {<<: *base, variables: {CMD: safe}, script: ["eval $CMD"]}\n',
    ],
    ids=[
        "repeated-merge-key",
        "duplicate-explicit-key",
        "sequence-used-as-merge",
        "unsupported-flow-merge",
    ],
)
def test_ambiguous_merge_input_never_claims_a_complete_effective_view(ambiguity: str) -> None:
    effective = _effective_events(ambiguity)
    assert not effective.complete


def test_merge_origin_chain_uses_anchor_work_budget_without_changing_raw_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from taintly.parsers import structural
    from taintly.parsers.structural import EventKind, walk_workflow

    count = 24
    rows = [".a0: &a0", "  variables:", "    CMD: $CI_COMMIT_TITLE"]
    for index in range(1, count):
        rows.extend([f".a{index}: &a{index}", f"  <<: *a{index - 1}"])
    rows.extend(["build:", f"  <<: *a{count - 1}", '  script:\n    - eval "$CMD"'])
    content = "\n".join(rows) + "\n"

    monkeypatch.setattr(structural.walker, "MAX_ANCHOR_WORK", 600)
    raw_events = tuple(walk_workflow(".gitlab-ci.yml", content=content))
    assert raw_events[-1].kind is not EventKind.CUTOFF
    assert any(
        event.kind is EventKind.LEAF_SCALAR and event.path == ("build", "variables", "CMD")
        for event in raw_events
    )

    effective = _effective_events(content)
    assert not effective.complete
    raw_with_keys = tuple(walk_workflow(".gitlab-ci.yml", content=content, include_keys=True))
    assert effective.events == raw_with_keys
    assert any(path.source_var == "CI_COMMIT_TITLE" for path in _taint_paths(content))
