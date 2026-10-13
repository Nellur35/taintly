"""Coverage disclosures for patterns that stop after finding matches."""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.models import (
    AuditReport,
    IncompletePatternMatches,
    Platform,
    Rule,
    Severity,
)


class _ResultPattern:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def check(self, content: str, lines: list[str]):
        self.calls += 1
        return self.result


def _rule(rule_id: str, pattern: _ResultPattern, *, anchor_aware: bool = False) -> Rule:
    return Rule(
        id=rule_id,
        title=f"{rule_id} title",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description="test rule",
        pattern=pattern,
        remediation="review",
        reference="https://example.com",
        anchor_aware=anchor_aware,
    )


def _engine_errors(findings):
    return [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]


def test_partial_matches_are_retained_and_later_rules_still_run():
    first = _ResultPattern(
        IncompletePatternMatches([(1, "retained evidence")], reason="state budget reached")
    )
    second = _ResultPattern([(1, "second rule evidence")])

    findings = scan_file(
        "workflow.yml",
        [_rule("TEST-PARTIAL", first), _rule("TEST-NEXT", second)],
        _content="run: echo ok\n",
    )

    errors = _engine_errors(findings)
    assert len(errors) == 1
    assert errors[0].severity is Severity.LOW
    assert "TEST-PARTIAL" in errors[0].title
    assert errors[0].file == "workflow.yml"
    assert "state budget reached" in errors[0].description
    assert [(f.rule_id, f.snippet) for f in findings if f.rule_id != "ENGINE-ERR"] == [
        ("TEST-PARTIAL", "retained evidence"),
        ("TEST-NEXT", "second rule evidence"),
    ]
    assert second.calls == 1


def test_empty_partial_result_is_not_a_clean_miss():
    partial = _ResultPattern(IncompletePatternMatches([], reason="analysis limit reached"))

    findings = scan_file(
        "empty.yml",
        [_rule("TEST-EMPTY-PARTIAL", partial)],
        _content="name: example\n",
    )

    errors = _engine_errors(findings)
    assert len(errors) == 1
    assert errors[0].severity is Severity.LOW
    assert "analysis limit reached" in errors[0].description


def test_partial_diagnostic_survives_anchor_aware_processing():
    partial = _ResultPattern(IncompletePatternMatches([(6, "anchor evidence")], reason="bounded"))
    content = """defaults: &defaults
  run: echo ok
jobs:
  build:
    steps:
      - <<: *defaults
"""

    findings = scan_file(
        "anchors.yml",
        [_rule("TEST-ANCHOR-PARTIAL", partial, anchor_aware=True)],
        _content=content,
    )

    errors = _engine_errors(findings)
    assert len(errors) == 1
    assert "TEST-ANCHOR-PARTIAL" in errors[0].title
    assert "bounded" in errors[0].description


def test_incomplete_anchor_recheck_does_not_suppress_original_matches():
    class _ExpansionPattern:
        calls = 0

        def check(self, content: str, lines: list[str]):
            self.calls += 1
            if self.calls == 1:
                return [(6, "original match")]
            return IncompletePatternMatches([], reason="expanded-anchor budget reached")

    pattern = _ExpansionPattern()
    content = """defaults: &defaults
  run: echo ok
jobs:
  build:
    steps:
      - <<: *defaults
"""

    findings = scan_file(
        "anchors.yml",
        [_rule("TEST-EXPANSION-PARTIAL", pattern, anchor_aware=True)],
        _content=content,
    )

    errors = _engine_errors(findings)
    assert pattern.calls == 2
    assert len(errors) == 1
    assert "expanded-anchor budget reached" in errors[0].description
    assert [(f.rule_id, f.snippet) for f in findings if f.rule_id != "ENGINE-ERR"] == [
        ("TEST-EXPANSION-PARTIAL", "original match")
    ]


def test_partial_reason_is_per_result_and_does_not_leak_between_scans():
    pattern = _ResultPattern(
        IncompletePatternMatches([(1, "first")], reason="first invocation cutoff")
    )
    rule = _rule("TEST-ISOLATION", pattern)

    first = scan_file("first.yml", [rule], _content="name: first\n")
    pattern.result = [(1, "complete result")]
    second = scan_file("second.yml", [rule], _content="name: second\n")

    assert len(_engine_errors(first)) == 1
    assert "first invocation cutoff" in _engine_errors(first)[0].description
    assert _engine_errors(second) == []
    assert [(f.rule_id, f.snippet) for f in second] == [("TEST-ISOLATION", "complete result")]


def test_incomplete_matches_keep_list_behavior_and_reason_is_immutable():
    matches = IncompletePatternMatches([(2, "evidence")], reason="per-call reason")

    assert isinstance(matches, list)
    assert matches == [(2, "evidence")]
    assert list(matches) == [(2, "evidence")]
    assert matches.reason == "per-call reason"
    try:
        matches._reason = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("the incomplete-analysis reason must be immutable")
    try:
        matches.reason = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("the public incomplete-analysis reason must be immutable")


def test_ordinary_list_results_remain_unchanged():
    pattern = _ResultPattern([(1, "ordinary evidence")])

    findings = scan_file(
        "ordinary.yml",
        [_rule("TEST-ORDINARY", pattern)],
        _content="name: example\n",
    )

    assert _engine_errors(findings) == []
    assert [(f.rule_id, f.snippet) for f in findings] == [("TEST-ORDINARY", "ordinary evidence")]


def test_medium_finding_and_coverage_error_surface_report_exit_11():
    from taintly.__main__ import _exit_for_severity

    pattern = _ResultPattern(IncompletePatternMatches([(1, "medium evidence")], reason="cutoff"))
    findings = scan_file("coverage.yml", [_rule("TEST-MEDIUM", pattern)], _content="name: x\n")
    report = AuditReport(repo_path=".", platform="github", findings=findings)

    assert len(report.engine_errors()) == 1
    with pytest.raises(SystemExit) as exc:
        _exit_for_severity(report)
    assert exc.value.code == 11
