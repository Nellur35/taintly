"""CI/CD security scorer — converts a list of findings into a 0-100 score.

Scoring model (cluster-based)
-----------------------------
Deductions are driven by distinct root-cause clusters, not by raw
finding count. An earlier revision ran a cluster track AND a legacy
per-severity track at the same time, which double-counted every
classified finding. The single-track model below fixes that.

    SCORE = 100
            - sum(cluster_deduction for cl in clusters)
            + bonuses
            clamped to [0, 100]

Per-cluster deduction = ``base_severity_points × confidence × exploitability``
plus a small capped spread bonus so genuine breadth across workflows
still matters. Review-needed clusters contribute 0. Findings with no
``finding_family`` fall through to a ``rule:<rule_id>``-keyed cluster in
``cluster_findings``, so they're still scored exactly once.

Cluster severity points:
    CRITICAL -> 14, HIGH -> 7, MEDIUM -> 3, LOW -> 1
Confidence weights:   high 1.0 / medium 0.6 / low 0.3
Exploitability weights: high 1.0 / medium 0.8 / low 0.5
Spread bonus: +1 per additional affected file, capped at +3 per cluster.

Per-category sub-scores are display-only breakdowns using the same
cluster-first model — they show teams *where* to focus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from taintly.families import cluster_findings
from taintly.models import Confidence, Finding, Platform, Severity

# Exploitability multipliers — applied ON TOP of confidence weights so the
# final deduction reflects both detector precision and contextual risk.
# HIGH is 1.0 (no adjustment); LOW is 0.5 so a rule firing in a benign
# context contributes half as much as the same rule firing in a workflow
# that sees secrets and write permissions.
_EXPLOITABILITY_WEIGHT: dict[str, float] = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.5,
}


def _weight(f: Finding) -> float:
    """Effective deduction weight for a finding.

    Review-needed patterns contribute 0 — they require human confirmation
    before they should move the score.  Otherwise the rule's confidence
    hint down-weights known-noisy detectors, and the context-derived
    exploitability tier (see workflow_context.compute_exploitability)
    further attenuates findings in workflows that don't actually offer
    attackers meaningful leverage.
    """
    if f.review_needed:
        return 0.0
    try:
        conf = Confidence(f.confidence).weight
    except ValueError:
        conf = 1.0
    expl = _EXPLOITABILITY_WEIGHT.get(f.exploitability or "medium", 0.8)
    return conf * expl


# ---------------------------------------------------------------------------
# Deduction / bonus constants
# ---------------------------------------------------------------------------

# Legacy per-severity constants — still used for the fallback track and
# the category-breakdown view so sub-scores remain stable for display.
_CRITICAL_PER = 10.0
_CRITICAL_CAP = 30.0
_HIGH_PER = 2.0
_HIGH_CAP = 30.0
_MEDIUM_PER = 0.5
_MEDIUM_CAP = 10.0

# Cluster-based deduction points per severity.  These are higher than the
# legacy per-finding values because ONE cluster now represents what used
# to be many findings.  Calibrated so a single CRITICAL+high-exploit
# cluster moves the score ~14 points, matching the old three-CRITICAL
# count-based deduction without compounding across correlated findings.
_CLUSTER_POINTS = {
    Severity.CRITICAL: 14.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}
# Total cluster-track deduction cap — guarantees the score still lives
# in [0, 100] even on catastrophically bad repos.
_CLUSTER_DEDUCTION_CAP = 70.0
# Spread bonus: +1 point per additional affected file, capped.
_SPREAD_BONUS_CAP = 3

_BONUS_NO_CRITICALS = 5
# Severity-headroom thresholds for the no_criticals bonus. The bonus's
# label suggests "no severe findings", but field test (jenkins.io
# 2026-04 retest, 3 HIGH findings still scored 100/A) showed that
# applying it whenever n_critical == 0 over-rewards repos with many
# HIGH findings. The bonus now also requires HIGH count below
# _BONUS_NO_CRITICALS_HIGH_CAP. A single HIGH finding still earns it
# (single-issue repos shouldn't lose the bonus on one finding) but
# 2+ HIGH lose it.
_BONUS_NO_CRITICALS_HIGH_CAP = 2
_BONUS_ALL_PINNED = 5  # zero pin rules fired for the platforms that were scanned
_BONUS_ALL_PERMISSIONS = 5  # zero permission rules fired for platforms with a perms concept

# Per-platform rule sets the bonuses are gated on. A Jenkins-only or
# GitLab-only scan does not earn the GitHub-permissions bonus by
# default — there's no GitHub permissions block for the rule to even
# evaluate, so the claim is vacuous and would inflate the score on
# repos the bonus rule pack doesn't actually apply to. Field test
# (jenkins.io, 2026-04) showed 4 HIGH findings producing 100/A
# entirely because of this gating gap.
_PIN_RULES_BY_PLATFORM: dict[Platform, frozenset[str]] = {
    Platform.GITHUB: frozenset({"SEC3-GH-001", "SEC3-GH-002"}),
    Platform.GITLAB: frozenset({"SEC3-GL-002"}),
    Platform.JENKINS: frozenset({"SEC3-JK-001"}),
}
# Permissions are a GitHub-specific concept. GitLab job rules and
# Jenkins agent labels don't map onto a "permissions block" the same
# way, so this bonus is intentionally GitHub-only.
_PERMS_RULES_BY_PLATFORM: dict[Platform, frozenset[str]] = {
    Platform.GITHUB: frozenset({"SEC2-GH-002"}),
}


def _platform_from_rule_id(rule_id: str) -> Platform | None:
    """Infer the platform a rule belongs to from its ID suffix
    (``-GH-`` / ``-GL-`` / ``-JK-``). Returns ``None`` for rule IDs
    that don't follow the convention (e.g. ``ENGINE-ERR``)."""
    if "-GH-" in rule_id:
        return Platform.GITHUB
    if "-GL-" in rule_id:
        return Platform.GITLAB
    if "-JK-" in rule_id:
        return Platform.JENKINS
    return None

# ---------------------------------------------------------------------------
# OWASP category metadata — weights must sum to ≤ 100 (leave headroom for rounding)
# ---------------------------------------------------------------------------

_CATEGORIES: list[tuple[str, str, int]] = [
    # (owasp_prefix, display_name, max_points)
    ("CICD-SEC-4", "Pipeline Execution (PPE)", 30),
    ("CICD-SEC-3", "Supply Chain", 25),
    ("CICD-SEC-6", "Credential Hygiene", 20),
    ("CICD-SEC-2", "Identity / Access", 10),
    ("CICD-SEC-1", "Flow Control", 5),
    ("CICD-SEC-9", "Artifact Integrity", 5),
    ("CICD-SEC-7", "System Config", 3),
    ("CICD-SEC-5", "PBAC", 1),
    ("CICD-SEC-10", "Logging", 1),
]

# Grade boundaries
_GRADES: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (0, "F"),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CategoryScore:
    owasp_id: str
    name: str
    max_points: int
    points: float
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    top_rule_id: str = ""

    @property
    def grade(self) -> str:
        pct = self.points / self.max_points if self.max_points else 1.0
        score = int(pct * 100)
        return _grade_for(score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "owasp_id": self.owasp_id,
            "name": self.name,
            "max_points": self.max_points,
            "points": round(self.points, 1),
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "top_rule_id": self.top_rule_id,
        }


@dataclass
class ScoreReport:
    total_score: int
    grade: str
    deductions: dict[str, float]
    bonuses: dict[str, int]
    categories: list[CategoryScore] = field(default_factory=list)
    finding_count: int = 0
    files_scanned: int = 0
    # Actual (uncapped) finding counts per severity — use these for display,
    # not back-calculated from capped deductions.
    counts: dict[str, int] = field(default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0})
    # Distinct root-cause clusters (see taintly.families.cluster_findings)
    distinct_risks: int = 0
    review_needed: int = 0
    # Security-debt profile — per-family qualitative labels (Strong /
    # Moderate / Weak) modelled on the improvement report's dimensional
    # view.  Complements the single letter grade by showing *where* the
    # debt sits rather than just *how much* of it there is.
    debt_profile: list[DebtDimension] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_score": self.total_score,
            "grade": self.grade,
            "deductions": {k: round(v, 1) for k, v in self.deductions.items()},
            "bonuses": self.bonuses,
            "categories": [c.to_dict() for c in self.categories],
            "finding_count": self.finding_count,
            "files_scanned": self.files_scanned,
            "counts": self.counts,
            "distinct_risks": self.distinct_risks,
            "review_needed": self.review_needed,
            "debt_profile": [d.to_dict() for d in self.debt_profile],
        }


@dataclass
class DebtDimension:
    """One row of the security-debt profile.

    ``label`` is one of ``Strong``, ``Moderate``, ``Weak``, ``Needs review``.
    The mapping is derived from the family's worst finding's exploitability
    and severity so the profile reflects real-world leverage, not raw
    rule-match volume.
    """

    family_id: str
    title: str
    label: str
    finding_count: int
    top_exploitability: str
    top_severity: str
    review_needed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "family_id": self.family_id,
            "title": self.title,
            "label": self.label,
            "finding_count": self.finding_count,
            "top_exploitability": self.top_exploitability,
            "top_severity": self.top_severity,
            "review_needed": self.review_needed,
        }


# ---------------------------------------------------------------------------
# Core scoring logic
# ---------------------------------------------------------------------------


def _grade_for(score: int) -> str:
    for threshold, grade in _GRADES:
        if score >= threshold:
            return grade
    return "F"


def _cluster_deduction(cluster) -> float:
    """Deduction for one root-cause cluster.

    Picks the single most-leverage finding in the cluster (worst by
    ``severity × exploitability × confidence``) and uses it as the
    representative "worst case" for this root cause.  Adds a spread
    bonus for breadth across workflows, capped so N identical files
    don't compound linearly.

    Review-needed clusters contribute 0 — they're human-triage items.
    """
    if cluster.review_needed:
        return 0.0

    def _finding_leverage(f) -> float:
        base = _CLUSTER_POINTS.get(f.severity, 0.0)
        try:
            conf = Confidence(f.confidence).weight
        except ValueError:
            conf = 1.0
        expl = _EXPLOITABILITY_WEIGHT.get(f.exploitability or "medium", 0.8)
        return base * conf * expl

    worst_leverage = max(
        (_finding_leverage(f) for f in cluster.findings),
        default=0.0,
    )
    spread = min(max(len(cluster.affected_files) - 1, 0), _SPREAD_BONUS_CAP)
    return worst_leverage + spread


def compute_score(
    findings: list[Finding],
    files_scanned: int = 0,
    platforms_scanned: set[Platform] | None = None,
) -> ScoreReport:
    """Compute a ScoreReport from a list of Finding objects.

    Single-track cluster-based scoring: one deduction per distinct
    root-cause cluster, weighted by confidence × exploitability with a
    small capped spread bonus for breadth. Findings with no family
    classification still get a ``rule:<rule_id>``-keyed cluster via
    ``cluster_findings``, so every finding contributes exactly once.

    The raw severity counts reported to consumers remain unweighted so
    the UI doesn't mislead about how many findings exist. The per-
    severity keys in ``deductions`` are kept at 0.0 for display-layer
    callers that expect the keys to be present.

    ``platforms_scanned`` is the set of platforms whose rules ran in
    the scan. The engine populates it from the rules it loaded; tests
    and ad-hoc callers can leave it ``None`` and the scorer infers it
    from the rule-ID suffixes on the findings (with the empty-findings
    case treated as "all platforms scanned" so a clean repo still
    earns its bonuses).
    """
    n_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in findings if f.severity == Severity.HIGH)
    n_medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    # Cluster-based deduction is the one and only math track. An earlier
    # revision ran a legacy per-severity track in parallel, which
    # double-counted every classified finding (once via its cluster,
    # once via the legacy severity cap).
    clusters = cluster_findings(findings)
    cluster_ded = sum(_cluster_deduction(cl) for cl in clusters)
    cluster_ded = min(cluster_ded, _CLUSTER_DEDUCTION_CAP)

    # Per-severity keys kept at 0.0 so callers inspecting deductions by
    # name don't break. The math lives entirely in ``CLUSTERS``.
    ded_critical = 0.0
    ded_high = 0.0
    ded_medium = 0.0

    # Bonuses — gated on platform applicability so a Jenkins-only or
    # GitLab-only scan can't collect a GitHub-permissions bonus the
    # rule pack would never have evaluated against.
    fired_rule_ids = {f.rule_id for f in findings}
    if platforms_scanned is None:
        inferred = {_platform_from_rule_id(f.rule_id) for f in findings}
        inferred.discard(None)
        platforms_scanned = inferred or {Platform.GITHUB, Platform.GITLAB, Platform.JENKINS}

    bonus_no_criticals = (
        _BONUS_NO_CRITICALS
        if n_critical == 0 and n_high < _BONUS_NO_CRITICALS_HIGH_CAP
        else 0
    )

    # all_pinned: for every scanned platform that HAS a pin rule, that
    # rule must not have fired. Platforms without a pin rule are
    # silently fine (they don't block the bonus).
    bonus_all_pinned = _BONUS_ALL_PINNED
    for plat in platforms_scanned:
        plat_pins = _PIN_RULES_BY_PLATFORM.get(plat, frozenset())
        if plat_pins and (fired_rule_ids & plat_pins):
            bonus_all_pinned = 0
            break

    # all_permissions: only applies when at least one scanned platform
    # HAS a permissions concept. On a Jenkins-only / GitLab-only scan
    # the bonus is not applicable and contributes 0 — the prior
    # behaviour of always-firing produced the field-test 100/A bug on
    # jenkins.io.
    perms_relevant = platforms_scanned & set(_PERMS_RULES_BY_PLATFORM)
    if not perms_relevant:
        bonus_all_perms = 0
    else:
        bonus_all_perms = _BONUS_ALL_PERMISSIONS
        for plat in perms_relevant:
            if fired_rule_ids & _PERMS_RULES_BY_PLATFORM[plat]:
                bonus_all_perms = 0
                break

    total_bonus = bonus_no_criticals + bonus_all_pinned + bonus_all_perms

    raw = 100 - cluster_ded + total_bonus
    total_score = max(0, min(100, int(raw)))

    deductions = {
        "CLUSTERS": -cluster_ded,
        "CRITICAL": -ded_critical,
        "HIGH": -ded_high,
        "MEDIUM": -ded_medium,
    }
    bonuses = {
        "no_criticals": bonus_no_criticals,
        "all_actions_pinned": bonus_all_pinned,
        "all_permissions": bonus_all_perms,
    }

    categories = _compute_categories(findings)

    distinct_risks = sum(1 for cl in clusters if not cl.review_needed)
    review_needed = sum(1 for cl in clusters if cl.review_needed)

    debt_profile = _compute_debt_profile(clusters)

    return ScoreReport(
        total_score=total_score,
        grade=_grade_for(total_score),
        deductions=deductions,
        bonuses=bonuses,
        categories=categories,
        finding_count=len(findings),
        files_scanned=files_scanned,
        counts={"CRITICAL": n_critical, "HIGH": n_high, "MEDIUM": n_medium},
        distinct_risks=distinct_risks,
        review_needed=review_needed,
        debt_profile=debt_profile,
    )


def _compute_debt_profile(clusters) -> list[DebtDimension]:
    """Build per-family qualitative debt labels from the cluster list.

    Mapping rationale — one label per family cluster:

    * ``Strong``       — no findings in this family
    * ``Needs review`` — only review-needed findings (e.g.
                         pull_request_target without exploitation signal)
    * ``Weak``         — at least one high-exploitability CRITICAL or
                         HIGH finding
    * ``Moderate``     — findings exist but none are both high-severity
                         AND high-exploitability

    Families with no findings are emitted too — that's the whole point
    of the profile: "where are we strong, where are we weak".
    """
    from taintly.families import iter_families  # local import avoids cycle

    by_family = {cl.family_id: cl for cl in clusters}
    rows: list[DebtDimension] = []
    for fam in iter_families():
        cluster = by_family.get(fam.id)
        if cluster is None:
            rows.append(
                DebtDimension(
                    family_id=fam.id,
                    title=fam.title,
                    label="Strong",
                    finding_count=0,
                    top_exploitability="-",
                    top_severity="-",
                )
            )
            continue

        # Resolve the worst (severity, exploitability) pair in the cluster
        _rank = {"low": 1, "medium": 2, "high": 3}
        worst = max(
            cluster.findings,
            key=lambda f: (f.severity.rank, _rank.get(f.exploitability, 2)),
        )
        top_sev = worst.severity.value
        top_expl = worst.exploitability or "medium"

        if cluster.review_needed:
            label = "Needs review"
        elif worst.severity >= Severity.HIGH and top_expl == "high":
            label = "Weak"
        else:
            label = "Moderate"

        rows.append(
            DebtDimension(
                family_id=fam.id,
                title=fam.title,
                label=label,
                finding_count=cluster.count,
                top_exploitability=top_expl,
                top_severity=top_sev,
                review_needed=cluster.review_needed,
            )
        )

    return rows


def _compute_categories(findings: list[Finding]) -> list[CategoryScore]:
    """Build per-OWASP-category sub-scores."""
    # Group findings by owasp_cicd prefix
    by_category: dict[str, list[Finding]] = {owasp: [] for owasp, _, _ in _CATEGORIES}
    for f in findings:
        for owasp, _, _ in _CATEGORIES:
            if f.owasp_cicd == owasp:
                by_category[owasp].append(f)
                break

    result = []
    for owasp, name, max_pts in _CATEGORIES:
        cat_findings = by_category[owasp]
        n_c = sum(1 for f in cat_findings if f.severity == Severity.CRITICAL)
        n_h = sum(1 for f in cat_findings if f.severity == Severity.HIGH)
        n_m = sum(1 for f in cat_findings if f.severity == Severity.MEDIUM)

        # Category deductions use the same confidence-weighted model as the
        # global score so the category grades stay consistent with the
        # headline number.
        w_c = sum(_weight(f) for f in cat_findings if f.severity == Severity.CRITICAL)
        w_h = sum(_weight(f) for f in cat_findings if f.severity == Severity.HIGH)
        w_m = sum(_weight(f) for f in cat_findings if f.severity == Severity.MEDIUM)
        cat_ded = (
            min(w_c * _CRITICAL_PER, _CRITICAL_CAP)
            + min(w_h * _HIGH_PER, _HIGH_CAP)
            + min(w_m * _MEDIUM_PER, _MEDIUM_CAP)
        )
        # Normalize deduction to [0, max_pts]
        total_possible_ded = _CRITICAL_CAP + _HIGH_CAP + _MEDIUM_CAP  # 70
        deduction_ratio = min(cat_ded / total_possible_ded, 1.0)
        points = max(0.0, max_pts * (1.0 - deduction_ratio))

        top_rule = ""
        if cat_findings:
            worst = max(cat_findings, key=lambda f: f.severity.rank)
            top_rule = worst.rule_id

        result.append(
            CategoryScore(
                owasp_id=owasp,
                name=name,
                max_points=max_pts,
                points=round(points, 1),
                finding_count=len(cat_findings),
                critical_count=n_c,
                high_count=n_h,
                medium_count=n_m,
                top_rule_id=top_rule,
            )
        )

    return result
