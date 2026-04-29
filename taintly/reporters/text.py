"""Human-readable text reporter with ANSI color support."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from taintly.families import cluster_findings
from taintly.models import AuditReport, Finding, Severity

from ._encoding import arrow_char, check_char, sep_char, to_ascii

if TYPE_CHECKING:
    from taintly.scorer import ScoreReport


COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


# Rule IDs that have a deterministic auto-fix available via ``--fix``.
# Keep in sync with taintly.fixes.ALL_FIXERS; used to pick a "Quick win".
_AUTO_FIXABLE_RULES = frozenset(
    {
        "SEC3-GH-001",  # pin action to SHA
        "SEC3-GH-002",  # pin action to SHA (docker / re-usable)
        "SEC3-GL-002",  # pin GitLab include ref
        "SEC2-GH-002",  # missing permissions block
        "SEC6-GH-001",  # persist-credentials on checkout
    }
)


# Confidence ordering for tie-breaking the top-risk / top-issues
# panels.  Higher number = stronger signal.  Used so that two findings
# at the same severity surface in the right order: confirmed-risk
# (high-confidence, not review_needed) beats analyst-review (medium /
# low confidence or review_needed) at the same severity rank.
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _surface_priority(f: Finding) -> tuple[int, int, int]:
    """Return a sort key (severity, not_review_needed, confidence_rank).

    Higher tuple sorts first.  ``review_needed=True`` becomes 0 in the
    second slot so confirmed-risk findings outrank analyst-review
    findings at the same severity.  ``confidence`` provides a final
    deterministic tier so ``high`` > ``medium`` > ``low``.
    """
    return (
        f.severity.rank,
        0 if f.review_needed else 1,
        _CONFIDENCE_RANK.get(f.confidence or "high", 0),
    )


def _top_issues(findings: list[Finding], n: int = 3) -> list[tuple[str, int, Severity, str]]:
    """Return the top ``n`` issues grouped by rule_id.

    Ranked by severity-then-confidence (so a HIGH-confidence
    confirmed-risk rule outranks a HIGH-but-review_needed rule),
    falling back to volume and rule_id for determinism.  Returns
    tuples of ``(rule_id, count, severity, title)``.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.rule_id, []).append(f)

    def _rank(item):
        rule_id, group = item
        # Use the first finding in the group as the representative for
        # the surface-priority key — all findings in a group share the
        # same rule and therefore the same review_needed / confidence.
        sev_rank, not_review, conf_rank = _surface_priority(group[0])
        return (-sev_rank, -not_review, -conf_rank, -len(group), rule_id)

    ranked = sorted(groups.items(), key=_rank)
    return [(rid, len(grp), grp[0].severity, grp[0].title) for rid, grp in ranked[:n]]


def _top_risk(findings: list[Finding]) -> Finding | None:
    """Pick the single worst finding (severity → confirmed-risk → confidence)."""
    if not findings:
        return None
    # max() keeps the first occurrence on ties, so this naturally
    # prefers the earliest-reported finding when the surface-priority
    # tuple ties exactly.  The richer key now makes a confirmed-risk
    # HIGH outrank a review_needed HIGH at the same severity rank.
    return max(findings, key=_surface_priority)


# Foreign-scanner inline-suppression markers we recognise when ranking
# the report's "Quick win" finding.  A finding whose source line
# carries one of these markers is demoted from quick-win consideration:
# the maintainer has clearly already reviewed it (under another tool)
# and surfacing it as the "first impression" would be misleading.
#
# The presence of these markers in code is interop, not endorsement —
# we do not honour the suppressions globally (that's the broader
# --respect-foreign-ignores feature).  We only de-prioritise these
# lines from the quick-win surface.
_FOREIGN_SUPPRESSION_MARKER_RE = re.compile(
    r"#\s*(?:"
    r"zizmor\s*:\s*ignore"      # zizmor (GitHub Actions auditor)
    r"|checkov\s*:\s*skip"      # checkov (IaC scanner)
    r"|nosec\b"                 # bandit
    r"|nosemgrep\b"             # semgrep
    r")",
    re.IGNORECASE,
)


def _has_foreign_suppression_marker(snippet: str) -> bool:
    """Return True when the finding's source-line snippet carries a
    recognised external-scanner inline ignore marker."""
    return bool(_FOREIGN_SUPPRESSION_MARKER_RE.search(snippet or ""))


def _quick_win(findings: list[Finding]) -> Finding | None:
    """Pick a finding whose rule has an auto-fix, preferring higher severity.

    Falls back to any finding with a short remediation string if no auto-fix
    rule fired. Returns ``None`` if neither heuristic applies.

    Findings whose source line carries a recognised foreign-scanner
    suppression marker (``# zizmor: ignore``, ``# checkov:skip``,
    ``# nosec``, ``# nosemgrep``) are demoted from quick-win
    consideration — they remain in the full findings list, but the
    report's first-impression surface skips lines the maintainer has
    already reviewed under another tool.
    """
    eligible = [f for f in findings if not _has_foreign_suppression_marker(f.snippet)]
    fixable = [f for f in eligible if f.rule_id in _AUTO_FIXABLE_RULES]
    if fixable:
        return max(fixable, key=lambda f: f.severity.rank)

    # Fallback: shortest remediation that's still actionable (non-empty one-liner).
    one_liner = [f for f in eligible if f.remediation and "\n" not in f.remediation.strip()]
    if one_liner:
        return max(one_liner, key=lambda f: f.severity.rank)
    return None


def _worst_severity_in(findings: list[Finding]) -> Severity:
    worst = Severity.INFO
    for f in findings:
        if f.severity > worst:
            worst = f.severity
    return worst


def _format_top_distinct_risks(
    report: AuditReport,
    c: dict[Severity, str],
    r: str,
    b: str,
    dim: str,
    n: int = 5,
) -> list[str]:
    """Build the 'Top distinct risks' block.

    Groups findings into root-cause clusters (see ``taintly.families``)
    and shows the top N by severity + spread.  This replaces the
    implicit "one alarming pile" narrative with a distinct-risk view so
    users see the number of problems they actually have to fix, not the
    number of rules that fired.

    Review-needed clusters (patterns that can be safe or dangerous
    depending on design intent) are shown in a separate block below
    so they don't crowd out confirmed risks.
    """
    out: list[str] = []
    if not report.findings:
        return out

    all_clusters = cluster_findings(report.findings)
    confirmed = [cl for cl in all_clusters if not cl.review_needed]
    review = [cl for cl in all_clusters if cl.review_needed]

    if confirmed:
        out.append(f"{b}Top distinct risks{r}")
        for cl in confirmed[:n]:
            worst = _worst_severity_in(cl.findings)
            files_n = len(cl.affected_files)
            plural = "s" if files_n != 1 else ""
            # Show context-derived exploitability alongside severity so
            # reviewers can see at a glance which clusters are worst
            # *right now in this repo* vs. worst-on-paper.
            expl = cl.top_exploitability
            expl_note = f" exploitability:{expl}" if expl != "medium" else ""
            out.append(
                f"  {c[worst]}[{worst.value}{expl_note}]{r} {b}{cl.title}{r} "
                f"{dim}({cl.count} finding{'s' if cl.count != 1 else ''} "
                f"across {files_n} file{plural}){r}"
            )
            if cl.why:
                # Wrap the first sentence of the "why" blurb for display.
                first_sentence = cl.why.split(". ")[0].rstrip(".")
                out.append(f"      {dim}{first_sentence}.{r}")
            # Show up to 3 component rule IDs for triage context.
            rule_preview = ", ".join(sorted(cl.rule_ids)[:3])
            if len(cl.rule_ids) > 3:
                rule_preview += f", +{len(cl.rule_ids) - 3} more"
            out.append(f"      {dim}Rules: {rule_preview}{r}")
        out.append("")

    if review:
        out.append(f"{b}Review-needed patterns{r}")
        out.append(
            f"  {dim}These patterns can be safe or dangerous depending on "
            f"design intent — confirm with a human before acting.{r}"
        )
        for cl in review[:n]:
            worst = _worst_severity_in(cl.findings)
            out.append(
                f"  {c[worst]}[{worst.value}]{r} {b}{cl.title}{r} "
                f"{dim}({cl.count} finding{'s' if cl.count != 1 else ''}){r}"
            )
        out.append("")

    return out


def _format_executive_summary(
    report: AuditReport,
    c: dict[Severity, str],
    r: str,
    b: str,
    dim: str,
    score_report: ScoreReport | None = None,
) -> list[str]:
    """Build the executive-summary block shown above the full findings list."""
    arr = arrow_char()
    out: list[str] = []

    out.append(f"{b}Summary{r}")
    out.append(f"  Files scanned:  {report.files_scanned}")
    out.append(f"  Total findings: {len(report.findings)}")
    # Distinct-risk count: the report should lead with "how many root-cause
    # clusters matter", not "how many rules fired".  This is the single most
    # important signal once a user gets past the summary line.
    clusters = cluster_findings(report.findings) if report.findings else []
    if clusters:
        distinct = len([cl for cl in clusters if not cl.review_needed])
        review = len([cl for cl in clusters if cl.review_needed])
        bits = [f"{distinct} confirmed"]
        if review:
            bits.append(f"{review} review-needed")
        out.append(f"  Distinct risks: {', '.join(bits)}")
    if score_report is not None:
        out.append(f"  Score:          {score_report.total_score}/100 ({score_report.grade})")
    sev_bits = []
    for sev in Severity:
        count = report.summary.get(sev.value, 0)
        if count:
            sev_bits.append(f"{c[sev]}{sev.value}:{count}{r}")
    if sev_bits:
        out.append(f"  By severity:    {'  '.join(sev_bits)}")
    out.append("")

    # Top distinct risks (root-cause clustered) — the primary value-add of
    # the v2 reporter.  This goes BEFORE the per-rule "Top 3 issues" view so
    # readers see the clustered picture first.
    out.extend(_format_top_distinct_risks(report, c, r, b, dim))

    top = _top_issues(report.findings, n=3)
    if top:
        out.append(f"{b}Top 3 issues{r}")
        for rule_id, count, sev, title in top:
            plural = "s" if count != 1 else ""
            out.append(
                f"  {c[sev]}[{sev.value}]{r} {b}{rule_id}{r} {arr} {count} finding{plural}: {title}"
            )
        out.append("")

    risk = _top_risk(report.findings)
    if risk is not None:
        out.append(f"{b}Top risk{r}")
        out.append(
            f"  {c[risk.severity]}[{risk.severity.value}]{r} {b}{risk.rule_id}{r}: {risk.title}"
        )
        out.append(f"  {dim}{risk.file}:{risk.line}{r}")
        out.append("")

    win = _quick_win(report.findings)
    if win is not None:
        auto = " (auto-fixable via --fix)" if win.rule_id in _AUTO_FIXABLE_RULES else ""
        out.append(f"{b}Quick win{r}")
        out.append(
            f"  {c[win.severity]}[{win.severity.value}]{r} {b}{win.rule_id}{r}: {win.title}{auto}"
        )
        out.append(f"  {dim}{win.file}:{win.line}{r}")
        if win.remediation:
            out.append(f"  Fix: {win.remediation.splitlines()[0]}")
        out.append("")

    return out


def format_text(
    report: AuditReport,
    use_color: bool = True,
    score_report: ScoreReport | None = None,
    verbose: bool = False,
    collapse_threshold: int = 5,
) -> str:
    """Render the audit report as text.

    When ``verbose=False`` (the default), any rule that fires more than
    ``collapse_threshold`` times collapses to a single summary block
    listing the affected files, with one sample finding shown in full.
    Pass ``verbose=True`` (CLI: ``--verbose``) to expand every finding.
    """
    c = COLORS if use_color else dict.fromkeys(COLORS, "")
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    dim = DIM if use_color else ""

    sep = sep_char()
    out = []
    out.append(f"\n{b}{sep * 3} TAINTLY REPORT {sep * 3}{r}")
    out.append(f"Repository: {report.repo_path}")
    out.append(f"Platform:   {report.platform or 'auto-detected'}")
    out.append(f"Files:      {report.files_scanned}")
    if report.rules_loaded:
        out.append(f"Rules:      {report.rules_loaded}")
    out.append("")

    # Coverage-degradation banner — surfaced above findings so a reader
    # skimming the report sees that ENGINE-ERR findings exist even when
    # filters or summaries hide them. ENGINE-ERR findings are ALSO
    # printed to stderr unconditionally (see __main__.py); this banner
    # is the in-stdout-report channel so a piped or saved report
    # carries the signal too.
    engine_errors = report.engine_errors()
    if engine_errors:
        warn_color = c.get(Severity.HIGH, "") if use_color else ""
        out.append(
            f"{warn_color}{b}! Coverage degraded on {len(engine_errors)} file(s){r}"
        )
        for f in engine_errors[:5]:
            out.append(f"  {arrow_char()} {f.file}: {f.title}")
        if len(engine_errors) > 5:
            out.append(f"  {arrow_char()} ... and {len(engine_errors) - 5} more")
        out.append(
            f"  {dim}File-scope rule coverage was incomplete on these files; "
            f"results below may be incomplete.{r}"
        )
        out.append("")

    if not report.findings or all(f.rule_id == "ENGINE-ERR" for f in report.findings):
        out.append(f"  {check_char()} No findings.")
        return to_ascii("\n".join(out))

    # Executive summary (score, counts, top issues, top risk, quick win)
    out.extend(_format_executive_summary(report, c, r, b, dim, score_report))

    # Group findings by rule_id so we can collapse repeats. Within each
    # group, sort by file then line for stable output.
    by_rule: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    for group in by_rule.values():
        group.sort(key=lambda f: (f.file, f.line))

    # Order rule groups by worst severity, then by group size (desc),
    # then by rule_id for determinism.
    rule_order = sorted(
        by_rule.items(),
        key=lambda kv: (-kv[1][0].severity.rank, -len(kv[1]), kv[0]),
    )

    out.append(f"{b}{sep * 3} Findings ({len(report.findings)}) {sep * 3}{r}")
    out.append("")

    for rule_id, group in rule_order:
        if not verbose and len(group) > collapse_threshold:
            out.extend(_format_collapsed_group(rule_id, group, c, r, b, dim))
        else:
            for f in group:
                out.extend(_format_finding(f, c, r, b, dim))

    if not verbose and any(len(g) > collapse_threshold for g in by_rule.values()):
        out.append(f"{dim}(some rules fire many times - pass --verbose to expand every finding){r}")

    # Flatten any rule-authored typography (em-dashes, smart quotes, ellipses
    # in titles / descriptions / remediations) to 7-bit ASCII before we
    # hand the string to stdout.  This is the only place that sees all of
    # the report content at once, so applying `to_ascii` here covers both
    # the reporter's own decorative glyphs and any Unicode that leaked in
    # through user / rule data.  Without this pass the em-dashes in rule
    # text surface as "â€"" mojibake on Windows PowerShell pipes.
    return to_ascii("\n".join(out))


def _format_finding(f: Finding, c: dict[Severity, str], r: str, b: str, dim: str) -> list[str]:
    """Render one finding in full detail."""
    markers = []
    if f.review_needed:
        markers.append("review-needed")
    if f.confidence and f.confidence != "high":
        markers.append(f"confidence:{f.confidence}")
    if f.exploitability and f.exploitability != "medium":
        markers.append(f"exploitability:{f.exploitability}")
    suffix = f" {dim}[{', '.join(markers)}]{r}" if markers else ""
    out = [
        f"  {c[f.severity]}[{f.severity.value}]{r} {b}{f.rule_id}{r}: {f.title}{suffix}",
        f"    File: {f.file}:{f.line}",
    ]
    if f.snippet:
        out.append(f"    Code: {f.snippet[:120]}")
    out.append(f"    {f.description[:200]}")
    if f.threat_narrative:
        out.append(f"    Threat: {f.threat_narrative}")
    if f.remediation:
        out.append(f"    Fix:  {f.remediation.split(chr(10))[0]}")
    tags = []
    if f.owasp_cicd:
        tags.append(f"OWASP:{f.owasp_cicd}")
    if f.stride:
        tags.append(f"STRIDE:{'+'.join(f.stride)}")
    if tags:
        out.append(f"    {' | '.join(tags)}")
    if f.incidents:
        out.append(f"    Incidents: {', '.join(f.incidents)}")
    out.append("")
    return out


def _format_collapsed_group(
    rule_id: str, group: list[Finding], c: dict[Severity, str], r: str, b: str, dim: str
) -> list[str]:
    """Render a collapsed summary for a rule that fires many times.

    Shows one summary line, the affected files (capped), and one
    representative sample finding in full. The full per-instance list
    is reachable via --verbose.
    """
    sample = group[0]
    files = sorted({f.file for f in group})
    n_files = len(files)
    files_preview = files[:5]
    files_str = ", ".join(files_preview)
    if n_files > len(files_preview):
        files_str += f", +{n_files - len(files_preview)} more"

    markers = []
    if sample.review_needed:
        markers.append("review-needed")
    if sample.confidence and sample.confidence != "high":
        markers.append(f"confidence:{sample.confidence}")
    if sample.exploitability and sample.exploitability != "medium":
        markers.append(f"exploitability:{sample.exploitability}")
    suffix = f" {dim}[{', '.join(markers)}]{r}" if markers else ""

    out = [
        f"  {c[sample.severity]}[{sample.severity.value}]{r} {b}{rule_id}{r}: "
        f"{sample.title}{suffix}",
        f"    {b}{len(group)} instances across {n_files} file(s){r}",
        f"    Files: {files_str}",
        f"    Sample: {sample.file}:{sample.line}",
    ]
    if sample.snippet:
        out.append(f"    Code:   {sample.snippet[:120]}")
    out.append(f"    {sample.description[:200]}")
    if sample.threat_narrative:
        out.append(f"    Threat: {sample.threat_narrative}")
    if sample.remediation:
        out.append(f"    Fix:    {sample.remediation.split(chr(10))[0]}")
    tags = []
    if sample.owasp_cicd:
        tags.append(f"OWASP:{sample.owasp_cicd}")
    if sample.stride:
        tags.append(f"STRIDE:{'+'.join(sample.stride)}")
    if tags:
        out.append(f"    {' | '.join(tags)}")
    out.append("")
    return out
