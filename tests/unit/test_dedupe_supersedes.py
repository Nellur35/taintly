"""Unit tests for the ``_dedupe_supersedes`` post-processor.

Covers the data-driven same-line dedup mechanism that collapses
canonical "one underlying bug, multiple overlapping rules" noise —
e.g. Jenkins ``sh "echo ${env.CHANGE_TITLE}"`` firing TAINT-JK-001
CRITICAL + SEC4-JK-002 HIGH + SEC4-JK-005 HIGH + SEC4-JK-008 MEDIUM
collapses to just the CRITICAL.

The rule-pack annotations (which rule supersedes which) are covered
indirectly by ``tests/integration`` scans.  These tests cover the
mechanism so a regression surfaces independently of any individual
rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from taintly.engine import _dedupe_supersedes, scan_repo
from taintly.models import Finding, Platform, RegexPattern, Rule, Severity


# ---------------------------------------------------------------------------
# Test-double for Rule.  The real Rule has many required fields irrelevant
# to dedup — we only need .id and .supersedes.  Using a stand-in keeps each
# test focused on the dedup logic.
# ---------------------------------------------------------------------------
@dataclass
class _StubRule:
    id: str
    supersedes: list[str] = field(default_factory=list)


def _finding(rule_id: str, *, file: str = "f.yml", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file=file,
        line=line,
    )


# ---------------------------------------------------------------------------
# Empty / no-op cases
# ---------------------------------------------------------------------------


def test_empty_findings_returns_empty():
    assert _dedupe_supersedes([], [_StubRule("A")]) == []


def test_no_supersedes_declared_returns_findings_unchanged():
    rules = [_StubRule("A"), _StubRule("B")]
    findings = [_finding("A"), _finding("B")]
    assert _dedupe_supersedes(findings, rules) == findings


def test_supersedes_declared_but_no_overlap_keeps_all():
    rules = [_StubRule("A", supersedes=["B"]), _StubRule("B")]
    # A on line 1; B on line 2 — different lines, no suppression.
    findings = [
        _finding("A", line=1),
        _finding("B", line=2),
    ]
    assert _dedupe_supersedes(findings, rules) == findings


# ---------------------------------------------------------------------------
# Single-supersede case
# ---------------------------------------------------------------------------


def test_supersede_same_line_drops_superseded():
    rules = [_StubRule("A", supersedes=["B"]), _StubRule("B")]
    findings = [_finding("A", line=5), _finding("B", line=5)]
    result = _dedupe_supersedes(findings, rules)
    assert [f.rule_id for f in result] == ["A"]


def test_supersede_different_files_independent():
    rules = [_StubRule("A", supersedes=["B"]), _StubRule("B")]
    # Same line number but different files — not the same source location.
    findings = [
        _finding("A", file="x.yml", line=3),
        _finding("B", file="y.yml", line=3),
    ]
    result = _dedupe_supersedes(findings, rules)
    assert {f.rule_id for f in result} == {"A", "B"}


# ---------------------------------------------------------------------------
# Multi-supersede case (the Jenkins canonical pattern)
# ---------------------------------------------------------------------------


def test_one_rule_supersedes_three_siblings():
    # Matches the TAINT-JK-001 → {SEC4-JK-002, SEC4-JK-005, SEC4-JK-008}
    # annotation shape.
    rules = [
        _StubRule("TAINT", supersedes=["S1", "S2", "S3"]),
        _StubRule("S1"),
        _StubRule("S2"),
        _StubRule("S3"),
    ]
    findings = [
        _finding("TAINT", line=10),
        _finding("S1", line=10),
        _finding("S2", line=10),
        _finding("S3", line=10),
    ]
    result = _dedupe_supersedes(findings, rules)
    assert [f.rule_id for f in result] == ["TAINT"]


def test_partial_overlap_keeps_non_superseded_lines():
    # TAINT on line 10; S1 on lines 10 + 20.  Only the line-10 S1
    # finding is suppressed; the line-20 one stands.
    rules = [_StubRule("TAINT", supersedes=["S1"]), _StubRule("S1")]
    findings = [
        _finding("TAINT", line=10),
        _finding("S1", line=10),
        _finding("S1", line=20),
    ]
    result = _dedupe_supersedes(findings, rules)
    assert [(f.rule_id, f.line) for f in result] == [
        ("TAINT", 10),
        ("S1", 20),
    ]


# ---------------------------------------------------------------------------
# Pathological / contract cases
# ---------------------------------------------------------------------------


def test_supersede_only_takes_effect_when_supersedor_fires():
    # B fires on line 5 but A does NOT — no suppression.
    rules = [_StubRule("A", supersedes=["B"]), _StubRule("B")]
    findings = [_finding("B", line=5)]
    result = _dedupe_supersedes(findings, rules)
    assert [f.rule_id for f in result] == ["B"]


def test_mutual_supersedes_is_not_silently_recursive():
    # Pathological config: A supersedes B AND B supersedes A.
    # Both fire on the same line. Conflicting specificity declarations
    # cannot justify choosing a winner: preserve both original findings.
    rules = [
        _StubRule("A", supersedes=["B"]),
        _StubRule("B", supersedes=["A"]),
    ]
    findings = [_finding("A", line=1), _finding("B", line=1)]
    result = _dedupe_supersedes(findings, rules)
    assert result == findings
    assert all(actual is original for actual, original in zip(result, findings))


def test_self_supersedes_cannot_erase_its_own_finding():
    findings = [_finding("A")]
    assert _dedupe_supersedes(findings, [_StubRule("A", ["A"])]) == findings


def test_three_member_cycle_preserves_members_and_regular_outgoing_suppression():
    rules = [
        _StubRule("A", ["B"]),
        _StubRule("B", ["C", "D"]),
        _StubRule("C", ["A"]),
        _StubRule("D"),
        _StubRule("E", ["A"]),
        _StubRule("F"),
    ]
    findings = [_finding(rule_id) for rule_id in ("F", "C", "D", "A", "E", "B")]
    result = _dedupe_supersedes(findings, rules)
    # Even E's incoming edge cannot choose between conflicting A/B/C.
    # B remains present and still legitimately supersedes noncyclic D.
    assert result == [findings[i] for i in (0, 1, 3, 4, 5)]
    assert all(actual is findings[i] for actual, i in zip(result, (0, 1, 3, 4, 5)))


def test_cycle_requires_all_members_at_the_same_file_and_line():
    rules = [_StubRule("A", ["B"]), _StubRule("B", ["C"]), _StubRule("C", ["A"])]
    findings = [
        _finding("A", file="x.yml", line=1),
        _finding("B", file="x.yml", line=1),
        _finding("C", file="y.yml", line=1),
        _finding("B", file="x.yml", line=2),
        _finding("C", file="x.yml", line=2),
    ]
    assert _dedupe_supersedes(findings, rules) == [findings[i] for i in (0, 2, 3)]


def test_acyclic_chain_keeps_existing_direct_edge_behavior():
    rules = [_StubRule("A", ["B"]), _StubRule("B", ["C"]), _StubRule("C")]
    findings = [_finding("C"), _finding("B"), _finding("A")]
    assert _dedupe_supersedes(findings, rules) == [findings[2]]


def test_absent_middle_rule_does_not_create_transitive_suppression():
    rules = [_StubRule("A", ["B"]), _StubRule("B", ["C"]), _StubRule("C")]
    findings = [_finding("A"), _finding("C")]
    assert _dedupe_supersedes(findings, rules) == findings


def test_supplied_cyclic_rules_retain_detected_findings_in_scan_repo(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "control.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo DEDUPE_CONTROL\n",
        encoding="utf-8",
    )
    rules = [
        Rule(
            id=rule_id,
            title="Authored supplied-rule deduplication control",
            severity=Severity.HIGH,
            platform=Platform.GITHUB,
            owasp_cicd="CICD-SEC-4",
            description="Mechanism control, not a security judgment.",
            pattern=RegexPattern(match="DEDUPE_CONTROL"),
            remediation="Authored control only.",
            reference="",
            supersedes=[other_id],
        )
        for rule_id, other_id in (("CONTROL-A", "CONTROL-B"), ("CONTROL-B", "CONTROL-A"))
    ]
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert len(reports) == 1
    assert reports[0].files_scanned == 1
    assert reports[0].engine_errors() == []
    assert [(f.rule_id, f.line, f.snippet) for f in reports[0].findings] == [
        ("CONTROL-A", 6, "- run: echo DEDUPE_CONTROL"),
        ("CONTROL-B", 6, "- run: echo DEDUPE_CONTROL"),
    ]
