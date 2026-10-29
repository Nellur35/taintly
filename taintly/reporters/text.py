"""Human-readable text reporter with ANSI color support."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import TYPE_CHECKING

from taintly.families import cluster_findings
from taintly.models import AuditReport, Finding, Severity

from ._encoding import arrow_char, check_char, sep_char, to_ascii
from ._encoding import strip_terminal_controls as _safe
from .evidence_ascii import format_evidence_trace

if TYPE_CHECKING:
    from taintly.scorer import ScoreReport


# Rule IDs whose findings are inventory items, not security findings to
# investigate.  These rules surface third-party dependencies in CI
# surface area at INFO severity with ``review_needed=True``.  They are
# designed to be snapshotted with ``--baseline`` and reviewed
# periodically by the user at their own cadence — the tool does not
# recommend a frequency.
INVENTORY_RULE_IDS: frozenset[str] = frozenset(
    {
        "SEC3-GH-006",
        "SEC3-GL-006",
        "SEC3-JK-005",
    }
)


def _security_findings(findings: list[Finding]) -> list[Finding]:
    """Risk candidates exclude inventory observations and scan diagnostics."""
    return [
        f for f in findings if f.rule_id not in INVENTORY_RULE_IDS and f.rule_id != "ENGINE-ERR"
    ]


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
        # Context enrichment can change severity and review state within
        # one rule. Rank and label the group by its worst actual finding.
        sev_rank, not_review, conf_rank = _surface_priority(max(group, key=_surface_priority))
        return (-sev_rank, -not_review, -conf_rank, -len(group), rule_id)

    ranked = sorted(groups.items(), key=_rank)
    out = []
    for rid, group in ranked[:n]:
        representative = max(group, key=_surface_priority)
        out.append((rid, len(group), representative.severity, representative.title))
    return out


def _review_details_key(f: Finding) -> str:
    """Only share details that are identical before display truncation.

    Location and source text are printed for every occurrence. All other
    serialized metadata must agree, including evidence notes, remediation,
    review state and provenance. Matching details do not prove a common
    root cause or execution path; this is presentation only.
    """
    details = f.to_dict()
    for field in ("file", "line", "snippet", "match_text"):
        details.pop(field)
    # Discovery confidence is currently absent from Finding.to_dict().
    details["discovery_confidence"] = f.discovery_confidence
    if f._evidence_trace is not None:
        details["evidence_trace"] = asdict(f._evidence_trace)
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


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
    r"zizmor\s*:\s*ignore"  # zizmor (GitHub Actions auditor)
    r"|checkov\s*:\s*skip"  # checkov (IaC scanner)
    r"|nosec\b"  # bandit
    r"|nosemgrep\b"  # semgrep
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

    all_clusters = cluster_findings(_security_findings(report.findings))
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


def _format_disclosure_block(report: AuditReport) -> list[str]:
    """Surface trust events that affected the scan: config-driven
    rule exclusions, repository-identity source, and auto-detected
    GitLab CI context.  Each line is omitted when the underlying
    state is its conservative default, so default-configuration
    scans see the same compact summary as before.
    """
    out: list[str] = []
    if report.excluded_rules_from_config:
        rules_list = ", ".join(report.excluded_rules_from_config)
        out.append(
            f"  Config exclusions: {len(report.excluded_rules_from_config)} "
            f"rule(s) from .taintly.yml ({rules_list})"
        )
    if report.repo_identity_source == "explicit":
        out.append(
            f"  Repository identity: explicit ({report.repo_identity_value}) via --github-repo"
        )
    elif report.repo_identity_source == "auto":
        out.append(
            f"  Repository identity: auto-detected from git remote "
            f"({report.repo_identity_value}) — pass --github-repo to override"
        )
    elif report.platform == "github" and report.repo_identity_source == "unset":
        out.append(
            "  Repository identity: unknown (no git remote, no --github-repo) "
            "— repo-mismatch suppression disabled"
        )
    if report.gitlab_ctx_detected:
        ctx_pairs = ", ".join(
            f"{k.upper()}={v}" for k, v in sorted(report.gitlab_ctx_detected.items())
        )
        out.append(f"  GitLab CI context: auto-detected ({ctx_pairs})")
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
    # Split: vulnerability findings vs third-party inventory items.
    # Inventory items surface CI surface-area to review periodically at
    # the user's chosen cadence; they are not findings to fix.
    vuln_findings = _security_findings(report.findings)
    inventory_findings = [f for f in report.findings if f.rule_id in INVENTORY_RULE_IDS]
    out.append(f"  Findings:       {len(vuln_findings)}")
    if inventory_findings:
        out.append(
            f"  Third-party in CI: {len(inventory_findings)}  "
            f"(review periodically; snapshot with --baseline)"
        )
    # Distinct-risk count: clusters from vulnerability findings only,
    # excluding inventory items so the "X confirmed" lead-line means
    # "X security clusters", not "X clusters including supply-chain
    # inventory the user has already chosen to live with".
    clusters = cluster_findings(vuln_findings) if vuln_findings else []
    if clusters:
        distinct = len([cl for cl in clusters if not cl.review_needed])
        review = len([cl for cl in clusters if cl.review_needed])
        bits = [f"{distinct} confirmed"]
        if review:
            bits.append(f"{review} review-needed")
        out.append(f"  Distinct risks: {', '.join(bits)}")
    if score_report is not None:
        if score_report.applicable:
            review_status = "; review pending" if score_report.review_needed else ""
            out.append(
                f"  Score:          {score_report.total_score}/100 "
                f"({score_report.grade}{review_status})"
            )
        else:
            out.append("  Score:          N/A (no applicable CI/CD configuration found)")
    sev_bits = []
    for sev in Severity:
        # Severity breakdown over vulnerability findings only — INFO
        # inventory items don't pad the INFO column.
        count = sum(1 for f in vuln_findings if f.severity is sev)
        if count:
            sev_bits.append(f"{c[sev]}{sev.value}:{count}{r}")
    if sev_bits:
        out.append(f"  By severity:    {'  '.join(sev_bits)}")
    out.extend(_format_disclosure_block(report))
    out.append("")

    # Top distinct risks (root-cause clustered) — the primary value-add of
    # the v2 reporter.  This goes BEFORE the per-rule "Top 3 issues" view so
    # readers see the clustered picture first.
    out.extend(_format_top_distinct_risks(report, c, r, b, dim))

    top = _top_issues(vuln_findings, n=3)
    if top:
        out.append(f"{b}Top 3 issues{r}")
        for rule_id, count, sev, title in top:
            plural = "s" if count != 1 else ""
            out.append(
                f"  {c[sev]}[{sev.value}]{r} {b}{rule_id}{r} {arr} {count} finding{plural}: {title}"
            )
        out.append("")

    risk = _top_risk(vuln_findings)
    if risk is not None:
        out.append(f"{b}Top risk{r}")
        out.append(
            f"  {c[risk.severity]}[{risk.severity.value}]{r} {b}{risk.rule_id}{r}: {risk.title}"
        )
        out.append(f"  {dim}{_safe(risk.file)}:{risk.line}{r}")
        out.append("")

    win = _quick_win(vuln_findings)
    if win is not None:
        auto = " (auto-fixable via --fix)" if win.rule_id in _AUTO_FIXABLE_RULES else ""
        out.append(f"{b}Quick win{r}")
        out.append(
            f"  {c[win.severity]}[{win.severity.value}]{r} {b}{win.rule_id}{r}: {win.title}{auto}"
        )
        out.append(f"  {dim}{_safe(win.file)}:{win.line}{r}")
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

    When ``verbose=False`` (the default), more than ``collapse_threshold``
    occurrences of one rule with identical review details share one detail
    block. Every occurrence retains its location and source preview.
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
    out.append(
        f"Coverage:   {report.semantic_coverage_status()} (semantic completeness is not proven)"
    )
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
        affected_files = len({f.file for f in engine_errors})
        out.append(f"{warn_color}{b}! Coverage degraded on {affected_files} file(s){r}")
        for f in engine_errors[:5]:
            out.append(f"  {arrow_char()} {_safe(f.file)}: {f.title}")
        if len(engine_errors) > 5:
            out.append(f"  {arrow_char()} ... and {len(engine_errors) - 5} more")
        out.append(
            f"  {dim}File-scope rule coverage was incomplete on these files; "
            f"results below may be incomplete.{r}"
        )
        out.append("")

    if not report.findings or all(f.rule_id == "ENGINE-ERR" for f in report.findings):
        if engine_errors:
            out.append("  No security findings reported; scan incomplete.")
        else:
            out.append(f"  {check_char()} No findings.")
        # Even on a clean scan, surface trust events that affected the
        # scope of what was checked: a "no findings" report on a config
        # that excludes rules is meaningfully different from "no
        # findings" on a config that excludes nothing.
        out.extend(_format_disclosure_block(report))
        return to_ascii("\n".join(out))

    # Executive summary (score, counts, top issues, top risk, quick win)
    out.extend(_format_executive_summary(report, c, r, b, dim, score_report))

    # Different witnesses or review decisions must never disappear behind
    # a sample from the same rule. Verbose mode still expands every finding.
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in report.findings:
        details = "" if verbose else _review_details_key(f)
        groups.setdefault((f.rule_id, details), []).append(f)
    for group in groups.values():
        group.sort(key=lambda f: (f.file, f.line))

    # Order rule groups by worst severity, then by group size (desc),
    # then by rule_id for determinism.
    group_order = sorted(
        groups.items(),
        key=lambda kv: (
            -max(f.severity.rank for f in kv[1]),
            -len(kv[1]),
            kv[0][0],
            kv[1][0].file,
            kv[1][0].line,
            kv[0][1],
        ),
    )

    total = len(report.findings)
    inventory_count = sum(1 for f in report.findings if f.rule_id in INVENTORY_RULE_IDS)
    vuln_count = len(_security_findings(report.findings))
    if inventory_count or engine_errors:
        parts = [f"{vuln_count} security findings"]
        if inventory_count:
            parts.append(f"{inventory_count} inventory")
        if engine_errors:
            parts.append(f"{len(engine_errors)} coverage warnings")
        header_count = f"{total} = {' + '.join(parts)}"
    else:
        header_count = str(total)
    out.append(f"{b}{sep * 3} Findings ({header_count}) {sep * 3}{r}")
    out.append("")

    collapsed = False
    for (_rule_id, _details), group in group_order:
        if not verbose and len(group) > collapse_threshold:
            out.extend(_format_collapsed_group(group, c, r, b, dim))
            collapsed = True
        else:
            for f in group:
                out.extend(_format_finding(f, c, r, b, dim))

    if collapsed:
        out.append(
            f"{dim}(identical review details shared - pass --verbose to expand every finding){r}"
        )

    # Flatten any rule-authored typography (em-dashes, smart quotes, ellipses
    # in titles / descriptions / remediations) to 7-bit ASCII before we
    # hand the string to stdout.  This is the only place that sees all of
    # the report content at once, so applying `to_ascii` here covers both
    # the reporter's own decorative glyphs and any Unicode that leaked in
    # through user / rule data.  Without this pass the em-dashes in rule
    # text surface as "â€"" mojibake on Windows PowerShell pipes.
    return to_ascii("\n".join(out))


def _finding_heading(f: Finding, c: dict[Severity, str], r: str, b: str, dim: str) -> str:
    """Use the same review markers for individual and shared detail blocks."""
    markers = []
    if f.review_needed:
        markers.append("review-needed")
    if f.confidence and f.confidence != "high":
        markers.append(f"confidence:{f.confidence}")
    if f.exploitability and f.exploitability != "medium":
        markers.append(f"exploitability:{f.exploitability}")
    if f.triage_needed:
        markers.append("triage-needed")
    suffix = f" {dim}[{_safe(', '.join(markers))}]{r}" if markers else ""
    return f"  {c[f.severity]}[{f.severity.value}]{r} {b}{_safe(f.rule_id)}{r}: {_safe(f.title)}{suffix}"


def _detail_lines(label: str, value: str) -> list[str]:
    """Preserve full multi-line advice without accepting forged report lines."""
    parts = value.splitlines() or [""]
    return [f"    {label}{_safe(parts[0])}", *(f"        {_safe(part)}" for part in parts[1:])]


def _format_review_details(f: Finding) -> list[str]:
    """Render review evidence and remediation in full, once per detail block."""
    out = _detail_lines("", f.description)
    if f.threat_narrative:
        out.extend(_detail_lines("Threat: ", f.threat_narrative))
    for note in f.context_notes:
        out.extend(_detail_lines("Context: ", note))
    if f._evidence_trace is not None:
        out.extend(format_evidence_trace(f._evidence_trace, f.file))
    if f.context_tags:
        out.append(f"    Context tags: {_safe(', '.join(f.context_tags))}")
    if f.suppression_reason:
        out.extend(_detail_lines("Suppression: ", f.suppression_reason))
    if f.calibration_reason:
        out.extend(_detail_lines("Calibration: ", f.calibration_reason))
    if f.remediation:
        out.extend(_detail_lines("Fix:  ", f.remediation))
    if f.reference:
        out.extend(_detail_lines("Reference: ", f.reference))
    if f.origin != "file":
        out.append(f"    Origin: {_safe(f.origin)}")
    if f.discovery_confidence != "high":
        out.append(f"    Discovery confidence: {_safe(f.discovery_confidence)}")
    if f.finding_family:
        out.append(f"    Family: {_safe(f.finding_family)}")
    if f.composition_tags:
        out.append(f"    Composition tags: {_safe(', '.join(sorted(f.composition_tags)))}")
    tags = []
    if f.owasp_cicd:
        tags.append(f"OWASP:{f.owasp_cicd}")
    if f.stride:
        tags.append(f"STRIDE:{'+'.join(f.stride)}")
    if tags:
        out.append(f"    {_safe(' | '.join(tags))}")
    if f.incidents:
        out.append(f"    Incidents: {_safe(', '.join(f.incidents))}")
    out.append("")
    return out


def _format_finding(f: Finding, c: dict[Severity, str], r: str, b: str, dim: str) -> list[str]:
    """Render one finding in full detail with a bounded source preview."""
    out = [
        _finding_heading(f, c, r, b, dim),
        f"    File: {_safe(f.file)}:{f.line}",
    ]
    if f.snippet:
        out.append(f"    Code: {_safe(f.snippet[:120])}")
    out.extend(_format_review_details(f))
    return out


def _format_collapsed_group(
    group: list[Finding], c: dict[Severity, str], r: str, b: str, dim: str
) -> list[str]:
    """Share identical review details while retaining every occurrence."""
    sample = group[0]
    n_files = len({f.file for f in group})
    out = [
        _finding_heading(sample, c, r, b, dim),
        f"    {b}{len(group)} instances across {n_files} file(s){r}",
        "    Occurrences:",
    ]
    for f in group:
        out.append(f"      {_safe(f.file)}:{f.line}")
        if f.snippet:
            out.append(f"        Code: {_safe(f.snippet[:120])}")
    out.extend(_format_review_details(sample))
    return out
