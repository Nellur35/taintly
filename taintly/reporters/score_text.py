"""Text reporter for the --score output."""

from __future__ import annotations

from taintly.scorer import ScoreReport

from ._encoding import (
    arrow_char,
    check_char,
    cross_char,
    em_dash_char,
    sep_char,
    to_ascii,
)

RESET = "\033[0m"
BOLD = "\033[1m"
_COLOR_A = "\033[92m"  # green
_COLOR_B = "\033[92m"  # green
_COLOR_C = "\033[93m"  # yellow
_COLOR_D = "\033[33m"  # orange-ish
_COLOR_F = "\033[91m"  # red

_GRADE_COLORS = {"A": _COLOR_A, "B": _COLOR_B, "C": _COLOR_C, "D": _COLOR_D, "F": _COLOR_F}


def _check(ok: bool) -> str:
    return check_char() if ok else cross_char()


def format_score(report: ScoreReport, use_color: bool = True) -> str:
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    gc = _GRADE_COLORS.get(report.grade, "") if use_color else ""
    sep = sep_char()

    lines = []
    lines.append(f"\n{b}{sep * 3} CI/CD SECURITY SCORE {sep * 3}{r}")
    lines.append("")
    lines.append(f"  Score: {b}{gc}{report.total_score}/100 ({report.grade}){r}")
    # Threat-model disclosure.  The score is computed against a fixed
    # public-OSS threat model; the user's deployment may differ in ways
    # taintly can't observe.  Surfacing this adjacent to the score (not
    # at the bottom of the report) ensures CI consumers see it.  This
    # is disclosure, NOT a basis for score adjustment — taintly takes
    # no position on what the user's deployment actually is.  The
    # phrase "required, not optional" is load-bearing — see
    # docs/decisions/threat-model-disclosure-not-adjustment.md.
    lines.append(
        f"  {b}Threat model:{r} public-OSS deployment "
        "(fork PRs reachable, runners shared, secrets repo-scoped)."
    )
    lines.append(
        "  Findings are exploitability-weighted against this model. "
        "Assessing fit to your deployment is required, not optional."
    )
    lines.append("  See docs/SCORING.md.")
    if report.distinct_risks or report.review_needed:
        bits = [f"{report.distinct_risks} confirmed cluster(s)"]
        if report.review_needed:
            bits.append(f"{report.review_needed} review-needed")
        lines.append(f"  Distinct risks: {', '.join(bits)}")
    lines.append("")

    arr = arrow_char()
    # Deductions — use actual counts, not back-calculated from capped deductions.
    # The primary track is cluster-based (distinct root causes); the
    # per-severity lines only cover unclassified fallback findings.
    lines.append(f"{b}Deductions:{r}")
    cluster_ded = report.deductions.get("CLUSTERS", 0.0)
    lines.append(
        f"  Clusters: {report.distinct_risks:>3} distinct      {arr}  {cluster_ded:>5.1f} pts"
    )
    n_c = report.counts.get("CRITICAL", 0)
    n_h = report.counts.get("HIGH", 0)
    n_m = report.counts.get("MEDIUM", 0)
    lines.append(
        f"  CRITICAL: {n_c:>3} finding(s)  {arr}  {report.deductions['CRITICAL']:>5.1f} pts  (unclassified)"
    )
    lines.append(
        f"  HIGH:     {n_h:>3} finding(s)  {arr}  {report.deductions['HIGH']:>5.1f} pts  (unclassified)"
    )
    lines.append(
        f"  MEDIUM:   {n_m:>3} finding(s)  {arr}  {report.deductions['MEDIUM']:>5.1f} pts  (unclassified)"
    )
    lines.append("")

    # Bonuses
    lines.append(f"{b}Bonuses:{r}")
    nc_ok = report.bonuses["no_criticals"] > 0
    pin_ok = report.bonuses["all_actions_pinned"] > 0
    per_ok = report.bonuses["all_permissions"] > 0
    lines.append(
        f"  {_check(nc_ok)}  No critical findings            {'+' if nc_ok else ' '}{report.bonuses['no_criticals']}"
    )
    lines.append(
        f"  {_check(pin_ok)}  All actions pinned to SHA       {'+' if pin_ok else ' '}{report.bonuses['all_actions_pinned']}"
    )
    lines.append(
        f"  {_check(per_ok)}  All permissions explicit         {'+' if per_ok else ' '}{report.bonuses['all_permissions']}"
    )
    lines.append("")

    # Per-category breakdown
    lines.append(f"{b}Breakdown by category:{r}")
    for cat in report.categories:
        if cat.finding_count == 0 and cat.points == cat.max_points:
            note = "clean"
        else:
            parts = []
            if cat.critical_count:
                parts.append(f"{cat.critical_count} CRITICAL")
            if cat.high_count:
                parts.append(f"{cat.high_count} HIGH")
            if cat.medium_count:
                parts.append(f"{cat.medium_count} MEDIUM")
            note = ", ".join(parts) if parts else "clean"
        bar = f"{cat.points:.0f}/{cat.max_points}"
        dash = em_dash_char()
        lines.append(f"  {cat.name:<30} {bar:>6}  {dash} {note}")

    # Security-debt profile — family-aligned qualitative labels.
    # The improvement report asked for this view because a single letter
    # grade hides WHERE the debt is.  Showing Strong/Moderate/Weak per
    # family tells a team which axis to invest in next.
    if report.debt_profile:
        lines.append("")
        lines.append(f"{b}Security debt profile:{r}")
        dash = em_dash_char()
        for dim in report.debt_profile:
            label_color = ""
            if use_color:
                if dim.label == "Strong":
                    label_color = _COLOR_A
                elif dim.label == "Moderate":
                    label_color = _COLOR_C
                elif dim.label == "Weak":
                    label_color = _COLOR_F
                else:  # Needs review
                    label_color = _COLOR_D
            label_cell = f"{label_color}{dim.label}{r}" if use_color else dim.label
            note = ""
            if dim.finding_count:
                note = f"  ({dim.finding_count} finding(s), expl:{dim.top_exploitability})"
            lines.append(f"  {dim.title:<38} {dash} {label_cell}{note}")

    # Final pass: flatten any non-ASCII glyph to a safe 7-bit equivalent so
    # the score block survives when piped into a non-UTF-8 terminal (e.g.
    # Windows PowerShell through cp1252).  See `_encoding.to_ascii` for the
    # mojibake rationale — identical story as the text reporter.
    return to_ascii("\n".join(lines))
