"""Unit tests for taintly/models.py.

Tests the properties that matter most and were previously unverified:
- Pattern types produce correct line numbers (not off-by-one)
- filter_severity boundaries are correct (< vs <=)
- Severity ordering is a valid total order
- AbsencePattern, ContextPattern, SequencePattern behave correctly
"""

from __future__ import annotations

import pytest

from taintly.models import (
    AbsencePattern,
    AuditReport,
    BlockPattern,
    ContextPattern,
    Finding,
    RegexPattern,
    SequencePattern,
    Severity,
)


# =============================================================================
# Severity ordering
# =============================================================================


def test_severity_total_order():
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for i in range(len(order)):
        for j in range(len(order)):
            if i < j:
                assert order[i] < order[j], f"{order[i]} should be < {order[j]}"
                assert order[j] > order[i]
            elif i == j:
                assert not (order[i] < order[j])
                assert not (order[i] > order[j])


def test_severity_ge_boundary():
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.CRITICAL >= Severity.HIGH
    assert not (Severity.MEDIUM >= Severity.HIGH)


# =============================================================================
# filter_severity — the < vs <= boundary
# =============================================================================


def _make_report(*severities: Severity) -> AuditReport:
    report = AuditReport(repo_path="/test", platform="github")
    for i, sev in enumerate(severities):
        report.add(
            Finding(
                rule_id=f"TEST-{i}",
                severity=sev,
                title="t",
                description="d",
                file="f.yml",
            )
        )
    report.summarize()
    return report


@pytest.mark.parametrize(
    "min_sev, kept, removed",
    [
        (Severity.HIGH, [Severity.HIGH, Severity.CRITICAL], [Severity.LOW, Severity.MEDIUM, Severity.INFO]),
        (Severity.MEDIUM, [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL], [Severity.LOW, Severity.INFO]),
        (Severity.INFO, [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL], []),
        (Severity.CRITICAL, [Severity.CRITICAL], [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]),
    ],
)
def test_filter_severity_boundaries(min_sev, kept, removed):
    report = _make_report(*kept, *removed)
    report.filter_severity(min_sev)
    found_severities = {f.severity for f in report.findings}
    for sev in kept:
        assert sev in found_severities, f"{sev} should survive filter_severity({min_sev})"
    for sev in removed:
        assert sev not in found_severities, f"{sev} should be removed by filter_severity({min_sev})"


def test_filter_severity_updates_summary():
    report = _make_report(Severity.CRITICAL, Severity.LOW)
    report.filter_severity(Severity.HIGH)
    assert report.summary["LOW"] == 0
    assert report.summary["CRITICAL"] == 1
    assert report.summary["total"] == 1


def test_filter_severity_at_exact_boundary():
    """MEDIUM min_severity must keep MEDIUM findings, not just above."""
    report = _make_report(Severity.MEDIUM)
    report.filter_severity(Severity.MEDIUM)
    assert len(report.findings) == 1, "MEDIUM finding should survive --min-severity MEDIUM"


# =============================================================================
# RegexPattern — line numbers and match correctness
# =============================================================================


def test_regex_pattern_line_number_is_1_indexed():
    """Line numbers in findings must be 1-indexed (first line = 1, not 0)."""
    content = "name: Test\non: push\nuses: actions/checkout@v4\n"
    lines = content.splitlines()
    p = RegexPattern(match=r"uses:.*@v\d")
    matches = p.check(content, lines)
    assert len(matches) == 1
    assert matches[0][0] == 3, f"Expected line 3, got {matches[0][0]}"


def test_regex_pattern_excludes_comment_lines():
    content = "# uses: actions/checkout@v4\nuses: actions/checkout@v4\n"
    lines = content.splitlines()
    p = RegexPattern(match=r"uses:.*@v\d", exclude=[r"^\s*#"])
    matches = p.check(content, lines)
    assert len(matches) == 1
    assert matches[0][0] == 2


def test_regex_pattern_no_false_match():
    content = "uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n"
    lines = content.splitlines()
    p = RegexPattern(match=r"uses:\s*([^@\s]+)@(?![a-f0-9]{40}\b)(\S+)")
    matches = p.check(content, lines)
    assert matches == [], "SHA-pinned action must not match unpinned-action rule"


def test_regex_pattern_snippet_is_stripped():
    content = "    - uses: actions/checkout@v4\n"
    lines = content.splitlines()
    p = RegexPattern(match=r"uses:.*@v\d")
    matches = p.check(content, lines)
    assert matches[0][1] == "- uses: actions/checkout@v4"


# =============================================================================
# AbsencePattern
# =============================================================================


def test_absence_pattern_fires_when_pattern_missing():
    content = "name: Test\non: push\n"
    lines = content.splitlines()
    p = AbsencePattern(absent=r"permissions:")
    matches = p.check(content, lines)
    assert len(matches) == 1


def test_absence_pattern_silent_when_pattern_present():
    content = "name: Test\npermissions:\n  contents: read\n"
    lines = content.splitlines()
    p = AbsencePattern(absent=r"permissions:")
    matches = p.check(content, lines)
    assert matches == []


# =============================================================================
# ContextPattern
# =============================================================================


def test_context_pattern_fires_when_both_present():
    content = "on: pull_request_target\njobs:\n  test:\n    steps:\n      - run: npm install\n"
    lines = content.splitlines()
    p = ContextPattern(anchor=r"pull_request_target", requires=r"npm (install|ci)")
    matches = p.check(content, lines)
    assert len(matches) >= 1


def test_context_pattern_silent_when_requires_absent():
    content = "on: pull_request\njobs:\n  test:\n    steps:\n      - run: npm install\n"
    lines = content.splitlines()
    p = ContextPattern(anchor=r"pull_request_target", requires=r"npm (install|ci)")
    matches = p.check(content, lines)
    assert matches == [], "Should not fire when 'requires' pattern is absent"


def test_context_pattern_requires_absent_suppresses():
    """requires_absent: if guard present, rule should not fire."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n  test:\n    if: github.event.pull_request.head.repo.fork == false\n"
        "    steps:\n      - run: npm install\n"
    )
    lines = content.splitlines()
    p = ContextPattern(
        anchor=r"pull_request_target",
        requires=r"npm (install|ci)",
        requires_absent=r"head\.repo\.fork",
    )
    matches = p.check(content, lines)
    assert matches == []


# =============================================================================
# SequencePattern
# =============================================================================


def test_sequence_pattern_fires_when_b_absent_in_window():
    content = "- uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n- run: npm test\n"
    lines = content.splitlines()
    p = SequencePattern(
        pattern_a=r"uses:\s*actions/checkout",
        absent_within=r"persist-credentials:\s*false",
        lookahead_lines=5,
    )
    matches = p.check(content, lines)
    assert len(matches) == 1


def test_sequence_pattern_silent_when_b_present_in_window():
    content = (
        "- uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1\n"
        "  with:\n"
        "    persist-credentials: false\n"
    )
    lines = content.splitlines()
    p = SequencePattern(
        pattern_a=r"uses:\s*actions/checkout",
        absent_within=r"persist-credentials:\s*false",
        lookahead_lines=5,
    )
    matches = p.check(content, lines)
    assert matches == []


# =============================================================================
# BlockPattern
# =============================================================================


def test_block_pattern_detects_match_inside_block():
    content = "jobs:\n  build:\n    steps:\n      - run: curl https://example.com | bash\n"
    lines = content.splitlines()
    p = BlockPattern(block_anchor=r"^jobs:", match=r"curl.*\|\s*(bash|sh)")
    matches = p.check(content, lines)
    assert len(matches) == 1


def test_block_pattern_does_not_match_outside_block():
    content = "curl https://example.com | bash\njobs:\n  build:\n    steps:\n      - run: echo ok\n"
    lines = content.splitlines()
    # anchor at "jobs:", match should only fire inside the block
    p = BlockPattern(block_anchor=r"^jobs:", match=r"curl.*\|\s*(bash|sh)")
    matches = p.check(content, lines)
    assert matches == [], "curl|bash before jobs: block should not match"


# =============================================================================
# AuditReport
# =============================================================================


def test_audit_report_summarize_counts_correctly():
    report = _make_report(
        Severity.CRITICAL, Severity.CRITICAL,
        Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
    )
    assert report.summary["CRITICAL"] == 2
    assert report.summary["HIGH"] == 1
    assert report.summary["total"] == 6


def test_audit_report_no_findings_is_clean():
    report = AuditReport(repo_path="/empty", platform="github")
    report.summarize()
    assert report.summary["total"] == 0
    assert all(report.summary[s] == 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
