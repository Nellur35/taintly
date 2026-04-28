"""Scorer v2 tests — confidence weighting, review-needed exclusion,
distinct-cluster counts.

The improvement report flagged two scoring flaws:

1. Repeated correlated findings disproportionately tanked the grade.
2. Low-precision / review-needed rules had the same impact as exact
   syntactic matches.

These tests lock in the fixes so a future refactor can't silently
regress them.
"""

from __future__ import annotations

from taintly.models import Finding, Platform, Severity
from taintly.scorer import compute_score


def _fn(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    *,
    confidence: str = "high",
    review_needed: bool = False,
    family: str = "supply_chain_immutability",
    owasp: str = "CICD-SEC-3",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=rule_id,
        description="",
        file="x.yml",
        line=1,
        owasp_cicd=owasp,
        finding_family=family,
        confidence=confidence,
        review_needed=review_needed,
    )


def test_low_confidence_finding_deducts_less_than_high():
    """A LOW-confidence HIGH finding must move the score less than a
    HIGH-confidence HIGH finding of the same severity.  Uses enough
    findings that per-severity deductions overcome the bonus floor so
    the weight actually shows up in the final score.
    """
    # SEC3-GH-001 is in the "pinned" bonus set, so it suppresses the
    # all_actions_pinned bonus — lets raw deductions drive the score.
    # SEC2-GH-002 similarly suppresses the permissions bonus.
    findings_high = [_fn("SEC3-GH-001", Severity.HIGH, confidence="high") for _ in range(20)]
    findings_high.append(_fn("SEC2-GH-002", Severity.CRITICAL, confidence="high", family="identity_access", owasp="CICD-SEC-2"))
    findings_low = [_fn("SEC3-GH-001", Severity.HIGH, confidence="low") for _ in range(20)]
    findings_low.append(_fn("SEC2-GH-002", Severity.CRITICAL, confidence="low", family="identity_access", owasp="CICD-SEC-2"))

    high_conf = compute_score(findings_high)
    low_conf = compute_score(findings_low)
    assert low_conf.total_score > high_conf.total_score


def test_review_needed_finding_does_not_deduct():
    """Review-needed items are human-triage — they must not touch the
    score at all.  The only effect should be the review-needed cluster
    count surfacing alongside the grade.
    """
    only_review = compute_score([
        _fn("R", Severity.CRITICAL, review_needed=True, family="privileged_pr_trigger", owasp="CICD-SEC-4"),
    ])
    assert only_review.total_score == 100
    assert only_review.review_needed == 1
    assert only_review.distinct_risks == 0


def test_distinct_risk_count_matches_clusters():
    """Correlated findings should produce ONE distinct risk, not N."""
    # Three findings in the same supply-chain family, different rule IDs.
    findings = [
        _fn("SEC3-GH-001"),
        _fn("SEC3-GH-002", severity=Severity.CRITICAL),
        _fn("SEC8-GH-003", severity=Severity.HIGH),
    ]
    score = compute_score(findings)
    assert score.distinct_risks == 1


def test_score_to_dict_includes_distinct_risks():
    score = compute_score([_fn("A", Severity.HIGH)])
    d = score.to_dict()
    assert "distinct_risks" in d
    assert "review_needed" in d


def test_counts_field_keeps_raw_totals():
    """The reported per-severity counts must remain raw/unweighted so the
    UI doesn't misrepresent the number of findings."""
    findings = [
        _fn("A", Severity.HIGH, confidence="low"),
        _fn("B", Severity.HIGH, confidence="low"),
        _fn("C", Severity.HIGH, confidence="low"),
    ]
    score = compute_score(findings)
    assert score.counts["HIGH"] == 3


# ---------------------------------------------------------------------------
# Exploitability weighting
# ---------------------------------------------------------------------------


def _fn_expl(rule_id: str, sev: Severity, exploitability: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=rule_id,
        description="",
        file="x.yml",
        line=1,
        owasp_cicd="CICD-SEC-3",
        finding_family="supply_chain_immutability",
        confidence="high",
        exploitability=exploitability,
    )


def test_low_exploitability_deducts_less_than_high():
    """Same severity + confidence + rule count — low-exploitability
    clusters should score better than high-exploitability clusters.
    """
    # Need enough findings to push past the bonus floor.
    high_expl = [_fn_expl("SEC3-GH-001", Severity.HIGH, "high") for _ in range(20)]
    low_expl = [_fn_expl("SEC3-GH-001", Severity.HIGH, "low") for _ in range(20)]
    # Suppress bonuses in both cases equally
    from taintly.models import Finding
    high_expl.append(Finding(
        rule_id="SEC2-GH-002", severity=Severity.CRITICAL, title="", description="",
        file="x.yml", line=1, owasp_cicd="CICD-SEC-2",
        finding_family="identity_access", confidence="high", exploitability="high",
    ))
    low_expl.append(Finding(
        rule_id="SEC2-GH-002", severity=Severity.CRITICAL, title="", description="",
        file="x.yml", line=1, owasp_cicd="CICD-SEC-2",
        finding_family="identity_access", confidence="high", exploitability="high",
    ))
    assert compute_score(low_expl).total_score > compute_score(high_expl).total_score


# ---------------------------------------------------------------------------
# Field-test regression: 4 HIGH Jenkins findings on jenkins.io produced
# 100/A in the 2026-04 field test. Root cause: every bonus is gated on
# a GitHub-only rule ID firing OR a CRITICAL count being non-zero, so a
# Jenkins-only repo with HIGH-only findings collected the full +15
# bonus floor.
# ---------------------------------------------------------------------------


def _jk_finding(rule_id: str, owasp: str, family: str) -> Finding:
    """Build a HIGH-severity Jenkins finding with the same exploitability
    a real Jenkinsfile scan would produce — withCredentials() supplies
    has_secrets_reference, env.CHANGE_BRANCH supplies has_fork_triggered,
    so script_injection / credential_persistence both compute to high.
    """
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title=rule_id,
        description="",
        file="Jenkinsfile",
        line=1,
        owasp_cicd=owasp,
        finding_family=family,
        confidence="high",
        exploitability="high",
    )


def test_jenkins_only_repo_does_not_collect_github_only_bonuses():
    """jenkins.io field-test regression: 4 HIGH findings (3x LOTP-JK-001
    + 1x SEC6-JK-002) on a Jenkinsfile produced 100/A in the 2026-04
    field test. Cluster deductions of 14 points were entirely masked by
    a +15 bonus floor (no_criticals + all_pinned + all_permissions),
    the last of which is GitHub-specific and was firing vacuously on a
    Jenkins-only scan.

    The fix gates all_permissions on whether at least one platform with
    a permissions concept was scanned. After the fix:
      * all_permissions bonus = 0 (Jenkins has no permissions concept)
      * cluster deductions are visible in the final score (< 100)
      * no_criticals and all_pinned still apply where they're earned
    """
    findings = [
        _jk_finding("LOTP-JK-001", "CICD-SEC-4", "script_injection"),
        _jk_finding("LOTP-JK-001", "CICD-SEC-4", "script_injection"),
        _jk_finding("LOTP-JK-001", "CICD-SEC-4", "script_injection"),
        _jk_finding("SEC6-JK-002", "CICD-SEC-6", "credential_persistence"),
    ]
    score = compute_score(findings)
    assert score.bonuses["all_permissions"] == 0, (
        "all_permissions bonus is GitHub-specific and must not fire on "
        f"a Jenkins-only scan — got {score.bonuses}"
    )
    assert score.total_score < 100, (
        f"4 HIGH Jenkins findings produced score {score.total_score}; "
        "cluster deductions were masked by an inapplicable bonus floor "
        f"(deductions={score.deductions}, bonuses={score.bonuses})"
    )


def test_jenkins_three_high_findings_loses_no_criticals_bonus():
    """jenkins.io 2026-04 RETEST regression: same Jenkinsfile, but
    after the SEC6-JK-002 audit narrowed its anchor, only 3 LOTP-JK-001
    findings remain. They cluster into a SINGLE script_injection cluster
    (same family + same file = no spread bonus), so cluster_deduction =
    one finding's leverage. With medium exploitability (Jenkinsfile has
    `withCredentials` but no fork-trigger signal): 7 * 1.0 * 0.8 = 5.6.

    With the no_criticals bonus (+5) and all_pinned bonus (+5; no
    @Library reference so SEC3-JK-001 can't fire) at +10 total, the
    score landed at 100 - 5.6 + 10 = 104, clamped to 100/A — the
    score was insensitive to the 3 HIGH findings.

    Fix: no_criticals bonus also requires HIGH count below
    _BONUS_NO_CRITICALS_HIGH_CAP (= 2). 3 HIGH → bonus drops to 0,
    score moves below 100.
    """
    findings = [
        _jk_finding("LOTP-JK-001", "CICD-SEC-4", "script_injection")
        for _ in range(3)
    ]
    # The Jenkinsfile context: has_secrets_reference=True (withCredentials),
    # has_fork_triggered=False → script_injection family computes to MEDIUM
    # exploitability under taintly.workflow_context.compute_exploitability.
    for f in findings:
        f.exploitability = "medium"
    score = compute_score(findings)
    assert score.bonuses["no_criticals"] == 0, (
        "no_criticals bonus must not fire when HIGH count >= 2 — got "
        f"{score.bonuses}"
    )
    assert score.total_score < 100, (
        f"3 HIGH findings still produced 100/A — score={score.total_score}, "
        f"deductions={score.deductions}, bonuses={score.bonuses}"
    )


def test_single_high_finding_keeps_no_criticals_bonus():
    """Threshold test: ONE HIGH finding still earns the no_criticals
    bonus. The bonus floor is preserved for near-clean repos; only 2+
    HIGH findings lose it.
    """
    findings = [
        _jk_finding("LOTP-JK-001", "CICD-SEC-4", "script_injection"),
    ]
    score = compute_score(findings)
    assert score.bonuses["no_criticals"] == 5, (
        "Single HIGH finding should still earn no_criticals bonus — got "
        f"{score.bonuses}"
    )


def test_clean_jenkins_only_repo_still_scores_a():
    """A clean Jenkins scan (no findings) must still produce 100/A —
    the platform-applicability gate must not penalise repos that have
    no findings to infer a platform from."""
    score = compute_score([], platforms_scanned={Platform.JENKINS})
    assert score.total_score == 100
    assert score.grade == "A"


def test_clean_repo_with_unknown_platforms_still_scores_a():
    """When platforms_scanned is omitted (the legacy / ad-hoc caller),
    a clean repo must still hit 100. Inference returns an empty set
    from no findings; the scorer treats that as 'all platforms'."""
    score = compute_score([])
    assert score.total_score == 100
    assert score.bonuses["all_permissions"] == 5  # GitHub assumed scanned


def test_sec9_gl_artifact_cluster_does_not_dominate_score():
    """gitlabhq field-test regression: ~106 of 220 findings were the
    SEC9-GL-001/003 artifact-integrity cluster, contributing to a 47/F
    score. The 2026-04-27 audit downgraded both to review_needed; a
    repo whose ONLY findings are from those rules must now score 100/A
    because review_needed clusters contribute 0 to deductions."""
    cluster_findings_list = [
        Finding(
            rule_id="SEC9-GL-001",
            severity=Severity.MEDIUM,
            title="artifacts no access",
            description="",
            file=f"job-{i}.yml",
            line=1,
            owasp_cicd="CICD-SEC-9",
            finding_family="release_integrity",
            confidence="low",
            review_needed=True,
        )
        for i in range(50)
    ] + [
        Finding(
            rule_id="SEC9-GL-003",
            severity=Severity.MEDIUM,
            title="cache no key",
            description="",
            file=f"job-{i}.yml",
            line=2,
            owasp_cicd="CICD-SEC-9",
            finding_family="release_integrity",
            confidence="low",
            review_needed=True,
        )
        for i in range(50)
    ]
    score = compute_score(cluster_findings_list)
    assert score.total_score == 100, (
        "100 SEC9-GL-001/003 review-needed findings must produce 100/A "
        f"(cluster deductions skip review_needed); got {score.total_score} "
        f"(deductions={score.deductions})"
    )
    # Findings still count for display — only the deduction is suppressed.
    assert score.finding_count == 100
    assert score.review_needed > 0
