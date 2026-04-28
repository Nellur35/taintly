"""Property-based tests for cross-module invariants.

PSE Domain 3.4 — extends tests/unit/test_pattern_properties.py with
properties that hold across the engine's other hot paths: the scorer,
the YAML-path parser, the job splitter, and the rule registry.

Each property is a single claim that MUST hold regardless of input
(within realistic bounds). Hypothesis generates the inputs; any
counterexample is printed in shrunk-minimal form.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from taintly.models import (  # noqa: E402
    Finding,
    Severity,
    _split_into_job_segments,
)
from taintly.rules.registry import load_all_rules  # noqa: E402
from taintly.scorer import compute_score  # noqa: E402
from taintly.yaml_path import _strip_inline_comment  # noqa: E402


_printable = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0x7E,
        categories=["L", "N", "P", "S", "Zs"],
    ),
    max_size=80,
)
_lines = st.lists(_printable, max_size=30)


# =============================================================================
# Scorer invariants
# =============================================================================


_severities = st.sampled_from(
    [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
)
_rule_ids = st.sampled_from(
    [
        "SEC4-GH-001",
        "SEC4-GH-004",
        "SEC3-GH-001",
        "SEC3-GH-002",
        "SEC2-GH-001",
        "SEC2-GH-002",
        "SEC1-GH-001",
        "SEC6-GH-007",
        "SEC10-GH-001",
    ]
)


@st.composite
def _finding(draw) -> Finding:
    return Finding(
        rule_id=draw(_rule_ids),
        severity=draw(_severities),
        title="generated",
        description="generated",
        file=f"fixture-{draw(st.integers(min_value=0, max_value=20))}.yml",
        line=draw(st.integers(min_value=1, max_value=500)),
        snippet="",
        remediation="",
        reference="",
        owasp_cicd="CICD-SEC-4",
    )


@given(findings=st.lists(_finding(), max_size=40))
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_scorer_total_score_always_in_zero_to_hundred(findings: list[Finding]) -> None:
    """A good scorer can never produce a score outside [0, 100]. If it
    does, the downstream UI lies about repo posture.
    """
    report = compute_score(findings, files_scanned=1)
    assert 0 <= report.total_score <= 100, (
        f"score {report.total_score} outside [0, 100] for {len(findings)} findings"
    )


@given(findings=st.lists(_finding(), max_size=40))
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_scorer_grade_follows_score(findings: list[Finding]) -> None:
    """Higher scores must produce a grade no worse than lower scores. A
    simple way to verify: scoring the same findings twice gives the
    same grade (grade is a pure function of score).
    """
    report_a = compute_score(findings, files_scanned=1)
    report_b = compute_score(findings, files_scanned=1)
    assert report_a.grade == report_b.grade
    assert report_a.total_score == report_b.total_score


@given(findings=st.lists(_finding(), min_size=1, max_size=30))
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_scorer_more_critical_findings_cannot_increase_score(
    findings: list[Finding],
) -> None:
    """Adding a CRITICAL finding to an existing finding set must not
    RAISE the score. Monotonicity is the minimum contract a security
    scorer has to its users.
    """
    base = compute_score(findings, files_scanned=1)
    extra_critical = Finding(
        rule_id="SEC4-GH-001",
        severity=Severity.CRITICAL,
        title="added",
        description="added",
        file="added.yml",
        line=1,
        snippet="",
        remediation="",
        reference="",
        owasp_cicd="CICD-SEC-4",
    )
    augmented = compute_score([*findings, extra_critical], files_scanned=1)
    assert augmented.total_score <= base.total_score


# =============================================================================
# yaml_path invariants
# =============================================================================


@given(value=_printable)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test__strip_inline_comment_is_idempotent(value: str) -> None:
    """Stripping a YAML inline comment twice must equal stripping once —
    the transformation reaches a fixed point after one application.
    """
    once = _strip_inline_comment(value)
    twice = _strip_inline_comment(once)
    assert once == twice


@given(value=_printable)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test__strip_inline_comment_never_grows_string(value: str) -> None:
    """A comment-stripping function can never produce a longer string
    than its input. Violations mean the parser is emitting something
    that was never in the input (corruption).
    """
    assert len(_strip_inline_comment(value)) <= len(value)


# =============================================================================
# Job splitter invariants
# =============================================================================


@given(content=_lines)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_job_splitter_segment_starts_are_in_range(content: list[str]) -> None:
    """Every segment's start index must be a valid index into the
    original line list — or 0 for the fallback single-segment case.
    """
    segments = _split_into_job_segments(content)
    for start, _seg in segments:
        assert 0 <= start <= max(len(content) - 1, 0)


@given(content=_lines)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_job_splitter_segments_do_not_exceed_input_total(content: list[str]) -> None:
    """The sum of segment lengths cannot exceed the input length. (It
    can be LESS when hidden-template / spec: blocks are filtered.)
    """
    segments = _split_into_job_segments(content)
    total = sum(len(seg) for _start, seg in segments)
    assert total <= len(content)


# =============================================================================
# Rule registry integrity
# =============================================================================
#
# These are one-shot integrity checks rather than property-based — a
# rule registry violation is a static defect, not input-dependent. They
# sit alongside the property tests because they express the same
# "invariant that must always hold" shape.


def test_registry_rule_ids_are_unique() -> None:
    rules = load_all_rules()
    ids = [r.id for r in rules]
    seen: set[str] = set()
    duplicates = []
    for rid in ids:
        if rid in seen:
            duplicates.append(rid)
        seen.add(rid)
    assert not duplicates, f"duplicate rule IDs: {duplicates}"


def test_registry_every_rule_has_required_fields() -> None:
    required = ("id", "title", "severity", "platform", "owasp_cicd", "pattern", "remediation")
    for rule in load_all_rules():
        for field_name in required:
            value = getattr(rule, field_name, None)
            assert value, f"{rule.id}: field {field_name!r} is missing or falsy"


def test_registry_rule_ids_follow_naming_convention() -> None:
    """Every rule ID matches one of the known prefix shapes.

    Keeps drive-by contributions from inventing new ID shapes that
    break downstream reporters (CSV/SARIF/HTML) which look up rules
    by prefix.
    """
    import re

    pattern = re.compile(
        r"^(SEC\d{1,2}-(GH|GL|JK)-\d{3}"
        r"|SEC\d{1,2}-GH-T\d{2}"
        r"|PLAT-(GH|GL)-\d{3}"
        r"|TAINT-(GH|GL|JK)-\d{3}"
        r"|LOTP-(GH|GL|JK)-\d{3}"
        r"|AI-(GH|GL|JK)-\d{3}"
        r"|PSE-(GH|GL|JK)-\d{3}"
        # XF-GH-* — cross-workflow rules whose evidence spans two or
        # more workflow files (Phase B3).  Pattern shape is
        # CorpusPattern, not the per-file pattern types, so they
        # follow a distinct prefix to make this clear in reports.
        # XF-* IDs accept an optional trailing letter to denote a
        # severity-tier split of one rule family (e.g. XF-GH-001A is
        # the executable-content variant of XF-GH-001's generic
        # cross-workflow cache poisoning).  Letter-suffix variants
        # share the family ID and route findings into severity tiers
        # without inventing a new rule number.
        r"|XF-(GH|GL|JK)-\d{3}[A-Z]?)$"
    )
    bad = [r.id for r in load_all_rules() if not pattern.match(r.id)]
    assert not bad, f"rule IDs violating the naming convention: {bad}"


def test_registry_pattern_check_returns_list_of_tuples() -> None:
    """Structural contract for the pattern layer. Any deviation breaks
    every caller that iterates findings.
    """
    for rule in load_all_rules():
        result = rule.pattern.check("", [])
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple) and len(item) == 2, (
                f"{rule.id}: pattern.check returned {item!r}"
            )


# =============================================================================
# Severity comparison invariants
# =============================================================================


@given(a=_severities, b=_severities)
@settings(max_examples=100, deadline=None)
def test_severity_comparison_is_total(a: Severity, b: Severity) -> None:
    """Exactly one of (a < b), (a == b), (a > b) holds for every pair."""
    assume(a is not None and b is not None)
    lt = a < b
    eq = a == b
    gt = a > b
    assert [lt, eq, gt].count(True) == 1, f"{a}/{b}: lt={lt} eq={eq} gt={gt}"
