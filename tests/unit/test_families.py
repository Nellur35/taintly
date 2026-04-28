"""Unit tests for finding-family classification and clustering.

These exercises the reporting-v2 improvements called out in the
improvement report:

* rules with the same root cause should cluster into ONE finding family
* confidence hints and review-needed flags should flow from the rule
  definition through to the Finding
* ``cluster_findings`` should rank clusters by severity, then by spread,
  and should keep review-needed clusters separable from confirmed risks
"""

from __future__ import annotations

from taintly.families import (
    classify_rule,
    cluster_findings,
    default_confidence,
    default_review_needed,
)
from taintly.models import Finding, Severity


def _finding(
    rule_id: str,
    *,
    severity: Severity = Severity.HIGH,
    owasp: str = "CICD-SEC-3",
    file: str = ".github/workflows/ci.yml",
    line: int = 1,
    family: str | None = None,
    confidence: str | None = None,
    review_needed: bool | None = None,
) -> Finding:
    """Build a Finding with family/confidence resolved the same way the
    engine does.  Lets tests mirror production classification in one line.
    """
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=f"{rule_id} fired",
        description="",
        file=file,
        line=line,
        owasp_cicd=owasp,
        finding_family=family if family is not None else classify_rule(rule_id, owasp),
        confidence=confidence if confidence is not None else default_confidence(rule_id),
        review_needed=review_needed if review_needed is not None else default_review_needed(rule_id),
    )


# ---------------------------------------------------------------------------
# classify_rule
# ---------------------------------------------------------------------------


def test_classify_maps_pinning_rules_to_same_family():
    """SEC3-GH-001, SEC3-GH-002, and SEC8-GH-003 describe the same root
    cause — they must all land in supply_chain_immutability so the report
    shows ONE cluster, not three unrelated findings.
    """
    assert classify_rule("SEC3-GH-001", "CICD-SEC-3") == "supply_chain_immutability"
    assert classify_rule("SEC3-GH-002", "CICD-SEC-3") == "supply_chain_immutability"
    assert classify_rule("SEC8-GH-003", "CICD-SEC-8") == "supply_chain_immutability"


def test_classify_falls_back_to_owasp_category():
    """Rules not explicitly listed should still get a family via the
    OWASP-prefix fallback — no finding should ever be uncategorized.
    """
    fam = classify_rule("SEC4-GH-999-unknown", "CICD-SEC-4")
    assert fam == "script_injection"


def test_classify_empty_when_no_info():
    assert classify_rule("UNKNOWN-RULE", "") == ""


# ---------------------------------------------------------------------------
# confidence / review-needed defaults
# ---------------------------------------------------------------------------


def test_default_confidence_is_high_for_exact_rules():
    """Syntactic-match rules should stay at HIGH confidence."""
    assert default_confidence("SEC3-GH-001") == "high"


def test_taint_rule_defaults_to_medium_confidence():
    """Shallow taint analysis is deliberately narrow — it must be
    surfaced as medium-confidence so it doesn't tank the grade alone.
    """
    assert default_confidence("TAINT-GH-001") == "medium"


def test_pull_request_target_is_review_needed_by_default():
    """pull_request_target is safe-or-dangerous by design.  The
    improvement report specifically calls this out."""
    assert default_review_needed("SEC4-GH-002") is True


def test_workflow_dispatch_string_input_is_review_needed():
    """SEC7-GH-004 fires on workflow_dispatch string inputs without an
    options: allowlist.  Many legitimate inputs (commit messages, PR
    URLs, version strings) genuinely need free text — route to the
    review-needed bucket so it doesn't get presented as a confirmed
    MEDIUM issue."""
    assert default_review_needed("SEC7-GH-004") is True


# ---------------------------------------------------------------------------
# cluster_findings
# ---------------------------------------------------------------------------


def test_cluster_groups_related_pinning_rules():
    """Three correlated pinning findings should collapse into ONE cluster."""
    findings = [
        _finding("SEC3-GH-001", severity=Severity.HIGH),
        _finding("SEC3-GH-002", severity=Severity.CRITICAL),
        _finding("SEC8-GH-003", severity=Severity.HIGH, owasp="CICD-SEC-8"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].family_id == "supply_chain_immutability"
    assert clusters[0].count == 3
    # All three rule IDs should be preserved as component signals.
    assert clusters[0].rule_ids == {"SEC3-GH-001", "SEC3-GH-002", "SEC8-GH-003"}


def test_cluster_orders_by_severity_then_count():
    """Highest-severity cluster must sort first even if a lower-severity
    cluster has more findings — the reporter needs the worst issue up top.
    """
    findings = [
        # Many medium-severity findings in the same family
        *[_finding("SEC1-GH-001", severity=Severity.MEDIUM, owasp="CICD-SEC-1", line=i) for i in range(5)],
        # One CRITICAL in a different family
        _finding("SEC4-GH-006", severity=Severity.CRITICAL, owasp="CICD-SEC-4"),
    ]
    clusters = cluster_findings(findings)
    assert clusters[0].top_severity_rank == Severity.CRITICAL.rank
    assert clusters[1].top_severity_rank == Severity.MEDIUM.rank


def test_cluster_separates_review_needed_from_confirmed():
    """Review-needed clusters (all members flagged review_needed) must be
    distinguishable so the reporter can show them in a separate block.
    """
    findings = [
        _finding("SEC3-GH-001", severity=Severity.HIGH),            # confirmed
        _finding("SEC4-GH-002", severity=Severity.HIGH, owasp="CICD-SEC-4"),  # review_needed default
    ]
    clusters = cluster_findings(findings)
    confirmed = [c for c in clusters if not c.review_needed]
    review = [c for c in clusters if c.review_needed]
    assert len(confirmed) == 1
    assert len(review) == 1
    assert confirmed[0].family_id == "supply_chain_immutability"


def test_cluster_counts_affected_files_across_jobs():
    """Spread across files should be tracked so the reporter can say
    "3 findings across 2 workflows"."""
    findings = [
        _finding("SEC3-GH-001", file=".github/workflows/a.yml"),
        _finding("SEC3-GH-001", file=".github/workflows/a.yml", line=2),
        _finding("SEC3-GH-001", file=".github/workflows/b.yml"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert len(clusters[0].affected_files) == 2
    assert clusters[0].count == 3
