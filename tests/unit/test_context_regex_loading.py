"""Contracts for scoped lazy compilation of secondary ContextPattern regexes."""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

import taintly.models as models
from taintly.models import ContextPattern


def _check(pattern: ContextPattern, content: str) -> list[tuple[int, str]]:
    return pattern.check(content, content.splitlines())


def test_direct_construction_still_compiles_all_regexes_eagerly():
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        pattern = ContextPattern(
            anchor=r"ANCHOR",
            requires=r"REQUIRED",
            requires_absent=r"ABSENT",
            exclude=[r"EXCLUDE"],
            anchor_job_exclude=r"JOB_EXCLUDE",
            anchor_step_exclude=r"STEP_EXCLUDE",
            anchor_step_require=r"STEP_REQUIRE",
        )

    compiled_sources = sorted(call.args[0] for call in compile_regex.call_args_list)
    assert compiled_sources == sorted(
        [
            r"ANCHOR",
            r"REQUIRED",
            r"ABSENT",
            r"EXCLUDE",
            r"JOB_EXCLUDE",
            r"STEP_EXCLUDE",
            r"STEP_REQUIRE",
        ]
    )
    assert isinstance(pattern._anchor_re, re.Pattern)
    assert isinstance(pattern._requires_re, re.Pattern)
    assert isinstance(pattern._requires_absent_re, re.Pattern)
    assert all(isinstance(item, re.Pattern) for item in pattern._excludes)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"anchor": "[", "requires": "required"},
        {"anchor": "anchor", "requires": "["},
        {"anchor": "anchor", "requires": "required", "requires_absent": "["},
        {"anchor": "anchor", "requires": "required", "exclude": ["["]},
        {"anchor": "anchor", "requires": "required", "anchor_job_exclude": "["},
        {"anchor": "anchor", "requires": "required", "anchor_step_exclude": "["},
        {"anchor": "anchor", "requires": "required", "anchor_step_require": "["},
    ],
)
def test_direct_construction_rejects_invalid_regexes(kwargs):
    with pytest.raises(re.error):
        ContextPattern(**kwargs)


def test_deferred_construction_compiles_only_requires_before_use():
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        with models._defer_context_regex_compilation():
            pattern = ContextPattern(
                anchor=r"ANCHOR",
                requires=r"REQUIRED",
                requires_absent=r"ABSENT",
                exclude=[r"EXCLUDE"],
                anchor_job_exclude=r"JOB_EXCLUDE",
                anchor_step_exclude=r"STEP_EXCLUDE",
                anchor_step_require=r"STEP_REQUIRE",
            )

    assert [call.args[0] for call in compile_regex.call_args_list] == [r"REQUIRED"]
    assert isinstance(pattern._requires_re, re.Pattern)


def test_failed_requires_gate_does_not_compile_secondary_regexes():
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        with models._defer_context_regex_compilation():
            pattern = ContextPattern(
                anchor=r"ANCHOR",
                requires=r"REQUIRED",
                requires_absent=r"ABSENT",
                exclude=[r"EXCLUDE"],
                anchor_job_exclude=r"JOB_EXCLUDE",
                anchor_step_exclude=r"STEP_EXCLUDE",
                anchor_step_require=r"STEP_REQUIRE",
            )
            compile_regex.reset_mock()
            assert _check(pattern, "ANCHOR\nno gate here") == []

    assert compile_regex.call_count == 0


def test_count_anchor_matches_compiles_anchor_even_when_requires_misses():
    content = "ANCHOR\nnot required\nANCHOR"
    lines = content.splitlines()
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        with models._defer_context_regex_compilation():
            pattern = ContextPattern(anchor=r"ANCHOR", requires=r"REQUIRED")
            compile_regex.reset_mock()
            assert pattern.count_anchor_matches(content, lines) == 2

    assert [call.args[0] for call in compile_regex.call_args_list] == [r"ANCHOR"]
    assert isinstance(pattern._anchor_re, re.Pattern)


def test_file_scope_returns_exact_anchor_lines_and_honors_excludes():
    content = """on: pull_request_target
jobs:
  build:
    steps:
      - run: install-deps
      - run: deploy
      - run: deploy # approved
"""
    pattern = ContextPattern(
        anchor=r"deploy",
        requires=r"install-deps",
        exclude=[r"approved"],
    )

    assert _check(pattern, content) == [(6, "- run: deploy")]


def test_job_scope_requires_and_anchor_must_share_job():
    content = """jobs:
  setup-only:
    steps:
      - run: install-deps
  deploy:
    steps:
      - run: deploy
      - run: install-deps
"""
    pattern = ContextPattern(anchor=r"- run: deploy", requires=r"install-deps", scope="job")

    assert _check(pattern, content) == [(7, "- run: deploy")]


def test_step_scope_requirement_is_co_located_with_anchor():
    content = """jobs:
  build:
    steps:
      - run: deploy
      - run: deploy # reviewed
        env:
          REVIEWED: true
"""
    pattern = ContextPattern(
        anchor=r"deploy",
        requires=r"jobs:",
        anchor_step_require=r"REVIEWED: true",
    )

    assert _check(pattern, content) == [(5, "- run: deploy # reviewed")]


def test_deferred_optional_suppressions_keep_job_and_step_scope():
    content = """jobs:
  blocked:
    marker: JOB_BLOCKER
    steps:
      - run: install-deps
      - run: deploy
  build:
    steps:
      - run: install-deps
      - run: deploy
        env: STEP_BLOCKER
      - run: deploy
"""
    with models._defer_context_regex_compilation():
        pattern = ContextPattern(
            anchor=r"- run: deploy",
            requires=r"install-deps",
            requires_absent=r"FILE_BLOCKER",
            exclude=[r"^\s*#"],
            anchor_job_exclude=r"JOB_BLOCKER",
            anchor_step_exclude=r"STEP_BLOCKER",
        )

    assert _check(pattern, content) == [(12, "- run: deploy")]
    assert isinstance(pattern._requires_absent_re, re.Pattern)
    assert isinstance(pattern._anchor_job_exclude_re, re.Pattern)
    assert isinstance(pattern._anchor_step_exclude_re, re.Pattern)


def test_deferred_regex_attributes_are_patterns_and_reused():
    with models._defer_context_regex_compilation():
        pattern = ContextPattern(
            anchor=r"ANCHOR",
            requires=r"REQUIRED",
            exclude=[r"EXCLUDE"],
            anchor_step_require=r"STEP_REQUIRE",
        )

    first_anchor = pattern._anchor_re
    first_excludes = pattern._excludes
    first_step_require = pattern._anchor_step_require_re
    assert isinstance(first_anchor, re.Pattern)
    assert isinstance(first_excludes, list)
    assert all(isinstance(item, re.Pattern) for item in first_excludes)
    assert isinstance(first_step_require, re.Pattern)
    assert pattern._anchor_re is first_anchor
    assert pattern._excludes is first_excludes
    assert pattern._anchor_step_require_re is first_step_require


def test_deferred_compilation_uses_construction_time_source_snapshot():
    with models._defer_context_regex_compilation():
        pattern = ContextPattern(
            anchor=r"ORIGINAL_ANCHOR",
            requires=r"ORIGINAL_REQUIRED",
            requires_absent=r"ORIGINAL_ABSENT",
            exclude=[r"ORIGINAL_EXCLUDE"],
        )

    pattern.anchor = r"MUTATED_ANCHOR"
    pattern.requires_absent = r"MUTATED_ABSENT"
    pattern.exclude = [r"MUTATED_EXCLUDE"]
    pattern.requires = r"MUTATED_REQUIRED"

    assert pattern._anchor_re.pattern == r"ORIGINAL_ANCHOR"
    assert pattern._requires_absent_re.pattern == r"ORIGINAL_ABSENT"
    assert [item.pattern for item in pattern._excludes] == [r"ORIGINAL_EXCLUDE"]
    assert pattern._requires_re.pattern == r"ORIGINAL_REQUIRED"


def test_defer_scope_restores_after_exception_and_nested_scope():
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        with pytest.raises(RuntimeError, match="sentinel"):
            with models._defer_context_regex_compilation():
                with models._defer_context_regex_compilation():
                    nested = ContextPattern(anchor=r"NESTED_ANCHOR", requires=r"NESTED_REQ")
                    compile_regex.reset_mock()
                    raise RuntimeError("sentinel")

        assert compile_regex.call_count == 0
        after = ContextPattern(anchor=r"AFTER_ANCHOR", requires=r"AFTER_REQ")

    assert [call.args[0] for call in compile_regex.call_args_list] == [
        r"AFTER_ANCHOR",
        r"AFTER_REQ",
    ]
    assert isinstance(nested._requires_re, re.Pattern)
    assert isinstance(after._anchor_re, re.Pattern)


def test_nested_scope_restores_outer_defer_state():
    with patch.object(models.re, "compile", wraps=re.compile) as compile_regex:
        with models._defer_context_regex_compilation():
            with models._defer_context_regex_compilation():
                ContextPattern(anchor=r"INNER_ANCHOR", requires=r"INNER_REQ")
            compile_regex.reset_mock()
            outer = ContextPattern(anchor=r"OUTER_ANCHOR", requires=r"OUTER_REQ")

    assert [call.args[0] for call in compile_regex.call_args_list] == [r"OUTER_REQ"]
    assert isinstance(outer._requires_re, re.Pattern)
