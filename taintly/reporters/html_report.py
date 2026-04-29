"""Self-contained HTML report generator for taintly.

Produces a single-file HTML document. No external CSS, JS, fonts, images,
CDN links, or analytics. All user-supplied content is HTML-escaped to
prevent XSS through a malicious rule title or finding field.

Layout (top to bottom):

    1. Cover header
    2. Executive summary card (grade, distinct-risk count, severity counts)
    3. Security debt profile (per-family qualitative labels)
    4. Score breakdown (SVG bar chart, only when a ScoreReport is provided)
    5. Top distinct risks (one expandable card per cluster)
    6. Review-needed patterns (separate, dimmer styling)
    7. All findings table (collapsed by default, supplements the cluster view)
    8. Footer

Why cards instead of one big table: a long flat findings table is hard to
scan on real repositories. Findings are clustered by root-cause family so
the reader sees a few distinct risks rather than a few hundred individual
hits. Each cluster card uses ``<details>``/``<summary>`` for native
collapse — no JavaScript required for the basic interaction.
"""

from __future__ import annotations

import os
from datetime import datetime
from html import escape
from typing import TYPE_CHECKING

from taintly.families import FindingCluster, cluster_findings
from taintly.models import AuditReport, Severity
from taintly.reporters.text import _AUTO_FIXABLE_RULES, _quick_win

if TYPE_CHECKING:
    from taintly.scorer import ScoreReport


def _relpath_for_display(file: str, repo_path: str) -> str:
    """Render a finding's file path relative to the scanned repo root.

    The HTML report previously rendered absolute paths
    (``C:\\Users\\asafy\\...`` / ``/home/user/...``), which leaks
    machine-local detail when reports are shared.  Rendering relative
    to ``report.repo_path`` keeps the column compact and portable.

    Falls back to the original path on any error (mismatched drives
    on Windows, non-existent path, etc.) so a quirky path never
    crashes the renderer.
    """
    if not repo_path or not file:
        return file
    try:
        rel = os.path.relpath(file, repo_path)
    except (ValueError, OSError):
        return file
    # Normalise to forward slashes for consistent reading regardless
    # of the host OS — matches the slashes already used elsewhere in
    # the report.
    return rel.replace(os.sep, "/")


# ---------------------------------------------------------------------------
# Styling — inlined, no external fonts or images
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --card: #f6f7f9;
  --border: #e1e4e8; --accent: #0969da;
  --sev-critical: #b31d28; --sev-high: #d1741f; --sev-medium: #9a6700;
  --sev-low: #0550ae; --sev-info: #57606a;
  --grade-a: #1a7f37; --grade-b: #3fa65a; --grade-c: #9a6700;
  --grade-d: #d1741f; --grade-f: #b31d28;
  --label-strong: #1a7f37; --label-moderate: #9a6700;
  --label-weak: #b31d28; --label-review: #0550ae;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #8b949e; --card: #161b22;
    --border: #30363d; --accent: #58a6ff;
    --sev-critical: #ff7b72; --sev-high: #ffa657; --sev-medium: #e3b341;
    --sev-low: #79c0ff; --sev-info: #8b949e;
    --grade-a: #3fb950; --grade-b: #56d364; --grade-c: #e3b341;
    --grade-d: #ffa657; --grade-f: #ff7b72;
    --label-strong: #3fb950; --label-moderate: #e3b341;
    --label-weak: #ff7b72; --label-review: #79c0ff;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
main { max-width: 1100px; margin: 0 auto; padding: 24px; }
header.cover { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
header.cover h1 { margin: 0 0 8px 0; font-size: 24px; }
header.cover .meta { color: var(--muted); font-size: 13px; }
header.cover .meta span { margin-right: 16px; }
section { margin-bottom: 32px; }
section h2 { font-size: 18px; margin: 0 0 12px 0; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
section h3 { font-size: 14px; margin: 16px 0 8px 0; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }

/* Executive summary card */
.summary-card { display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center;
                background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.grade-box {
  display: inline-flex; flex-direction: column; align-items: center; justify-content: center;
  width: 96px; height: 96px; border-radius: 12px; border: 3px solid currentColor;
  font-weight: 700; line-height: 1;
}
.grade-box .grade { font-size: 40px; }
.grade-box .score { font-size: 13px; margin-top: 4px; }
.grade-A { color: var(--grade-a); }
.grade-B { color: var(--grade-b); }
.grade-C { color: var(--grade-c); }
.grade-D { color: var(--grade-d); }
.grade-F { color: var(--grade-f); }
.summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px 20px; }
.stat .num { font-size: 22px; font-weight: 700; line-height: 1; }
.stat .lbl { font-size: 12px; color: var(--muted); margin-top: 2px; }
.summary-counts { grid-column: 1 / -1; padding-top: 12px; border-top: 1px solid var(--border);
                  display: flex; flex-wrap: wrap; gap: 8px 14px; }

/* Severity / exploitability / family labels */
.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
  font-weight: 700; color: #fff; letter-spacing: 0.02em;
}
.sev-CRITICAL { background: var(--sev-critical); }
.sev-HIGH { background: var(--sev-high); }
.sev-MEDIUM { background: var(--sev-medium); }
.sev-LOW { background: var(--sev-low); }
.sev-INFO { background: var(--sev-info); }
.expl-badge { display: inline-block; padding: 2px 6px; border-radius: 8px; font-size: 11px;
              border: 1px solid var(--border); color: var(--muted); margin-left: 4px; }
.expl-high { color: var(--sev-critical); border-color: var(--sev-critical); }
.expl-medium { color: var(--sev-medium); border-color: var(--sev-medium); }
.expl-low { color: var(--muted); }

/* Debt profile grid */
.debt-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 8px; }
.debt-row { display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center;
            padding: 8px 12px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; }
.debt-name { font-weight: 600; }
.debt-meta { color: var(--muted); font-size: 12px; }
.debt-label { font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 10px;
              border: 1px solid currentColor; }
.label-Strong { color: var(--label-strong); }
.label-Moderate { color: var(--label-moderate); }
.label-Weak { color: var(--label-weak); }
.label-Needs.review, .label-Needs-review { color: var(--label-review); }

/* Cluster cards */
.cluster {
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  margin-bottom: 12px; border-left: 4px solid var(--border); padding: 0;
}
.cluster.sev-card-CRITICAL { border-left-color: var(--sev-critical); }
.cluster.sev-card-HIGH     { border-left-color: var(--sev-high); }
.cluster.sev-card-MEDIUM   { border-left-color: var(--sev-medium); }
.cluster.sev-card-LOW      { border-left-color: var(--sev-low); }
.cluster.review-needed     { border-left-color: var(--label-review); opacity: 0.92; }
.cluster summary {
  /* Flexbox, not grid. The `::before` disclosure triangle is a grid
     item per the CSS Grid spec, so the previous `auto 1fr auto` grid
     had THREE columns for FOUR items (triangle + badges + title +
     counts). The counts wrapped to an implicit second row in some
     browsers and collapsed the title column to zero width in others,
     producing the "empty title field" rendering bug. Flex absorbs the
     pseudo-element naturally (it just sits inline with the spans) and
     `flex: 1` on the title makes it grow and push counts to the right. */
  list-style: none; cursor: pointer; padding: 12px 16px; user-select: none;
  display: flex; align-items: center; gap: 10px;
}
.cluster summary::-webkit-details-marker { display: none; }
.cluster summary::before {
  /* U+25B8 BLACK RIGHT-POINTING SMALL TRIANGLE, written as a CSS hex
     escape ("\\25B8") so the generated HTML stays pure ASCII. Writing
     the raw glyph would embed two UTF-8 bytes that get re-decoded as
     cp1252 mojibake when the report is piped through Windows PowerShell. */
  content: "\\25B8"; color: var(--muted); font-size: 12px; transition: transform 0.15s;
  transform: rotate(0deg); display: inline-block; flex: none;
}
.cluster[open] summary::before { transform: rotate(90deg); }
.cluster .cluster-title { font-weight: 600; flex: 1; min-width: 0; }
.cluster .cluster-counts { color: var(--muted); font-size: 12px; white-space: nowrap; flex: none; }
.cluster-body { padding: 0 16px 16px 16px; border-top: 1px solid var(--border); }
.cluster-body .why { color: var(--muted); margin: 12px 0 8px 0; }
.cluster-body .rule-ids { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
.cluster-body .rule-ids code { background: transparent; padding: 0; }

/* Findings table inside a cluster */
.cluster-findings { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
.cluster-findings th, .cluster-findings td { text-align: left; padding: 6px 10px;
                                              border-bottom: 1px solid var(--border); vertical-align: top; }
.cluster-findings th { color: var(--muted); font-weight: 600; font-size: 11px;
                       text-transform: uppercase; letter-spacing: 0.04em; }
.cluster-findings tr:last-child td { border-bottom: 0; }
.cluster-findings .file { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
                          font-size: 12px; color: var(--muted); }

/* Quick win callout */
.callout { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--accent);
           border-radius: 6px; padding: 12px 16px; margin-bottom: 12px; }
.callout-label { font-size: 11px; font-weight: 700; color: var(--accent); text-transform: uppercase;
                 letter-spacing: 0.06em; margin-bottom: 4px; }
.callout .fix { color: var(--muted); font-size: 13px; margin-top: 4px; }

/* SVG bar chart */
.bar-label { fill: var(--fg); font-size: 12px; }
.bar-track { fill: var(--border); }
.bar-fill { fill: var(--accent); }
.bar-caption { fill: var(--muted); font-size: 11px; }

/* Supplemental flat findings table (collapsed by default) */
.flat-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.flat-table th, .flat-table td { text-align: left; padding: 6px 10px;
                                  border-bottom: 1px solid var(--border); vertical-align: top; }
.flat-table th { background: var(--card); font-weight: 600; }

/* Misc */
code, pre {
  font: 12px/1.45 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  background: var(--card); border-radius: 4px;
}
code { padding: 1px 4px; }
pre { padding: 8px 10px; overflow-x: auto; border: 1px solid var(--border); margin: 4px 0; }
.tag { display: inline-block; padding: 1px 6px; background: var(--card);
       border: 1px solid var(--border); border-radius: 4px; font-size: 11px;
       margin-right: 6px; color: var(--muted); }
footer { color: var(--muted); font-size: 12px; text-align: center;
         padding: 20px 0; border-top: 1px solid var(--border); margin-top: 32px; }
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _e(s: object) -> str:
    """HTML-escape any value (cast to str first)."""
    return escape("" if s is None else str(s), quote=True)


def _grade_class(grade: str) -> str:
    return f"grade-{escape(grade[:1].upper(), quote=True)}"


def _severity_badge(sev: Severity) -> str:
    return f'<span class="sev-badge sev-{sev.value}">{sev.value}</span>'


def _expl_badge(expl: str | None) -> str:
    """Render an exploitability marker, but only when it's worth showing."""
    if not expl or expl == "medium":
        return ""
    return f'<span class="expl-badge expl-{_e(expl)}">expl:{_e(expl)}</span>'


def _bar_chart(items: list[tuple[str, float, float]], width: int = 360) -> str:
    """Render a horizontal bar chart as inline SVG.

    ``items`` is ``[(label, value, max_value), ...]``.  The returned SVG has a
    ``role="img"``, a ``<title>`` and ``<desc>`` child, and per-category
    captions showing the fill ratio.
    """
    if not items:
        return '<svg role="img" aria-label="No data" width="0" height="0"></svg>'

    row_h = 28
    label_w = 140
    bar_w = max(60, width - label_w - 80)
    pad_top = 28
    pad_bot = 8
    height = pad_top + row_h * len(items) + pad_bot

    parts: list[str] = []
    # Responsive: the viewBox keeps the drawing coordinates fixed while
    # ``width=100%`` lets the browser scale the SVG to its container on
    # narrow viewports.  preserveAspectRatio="xMinYMid meet" pins the
    # left edge so the label column stays aligned under scaling.
    parts.append(
        f'<svg role="img" width="100%" height="{height}" '
        f'viewBox="0 0 {width} {height}" preserveAspectRatio="xMinYMid meet" '
        f'style="max-width:{width}px" xmlns="http://www.w3.org/2000/svg">'
    )
    parts.append("<title>Score breakdown by OWASP category</title>")
    parts.append(
        "<desc>Horizontal bar chart showing points earned versus maximum points "
        "for each OWASP CI/CD category.</desc>"
    )
    for i, (label, value, max_value) in enumerate(items):
        y = pad_top + i * row_h
        bar_y = y + 4
        bar_h = 14
        ratio = 0.0 if max_value <= 0 else max(0.0, min(1.0, value / max_value))
        fill_w = bar_w * ratio
        label_safe = _e(label)
        parts.append(f'<text class="bar-label" x="0" y="{y + 14}">{label_safe}</text>')
        parts.append(
            f'<rect class="bar-track" x="{label_w}" y="{bar_y}" '
            f'width="{bar_w}" height="{bar_h}" rx="3"/>'
        )
        parts.append(
            f'<rect class="bar-fill" x="{label_w}" y="{bar_y}" '
            f'width="{fill_w:.1f}" height="{bar_h}" rx="3"/>'
        )
        parts.append(
            f'<text class="bar-caption" x="{label_w + bar_w + 6}" y="{y + 14}">'
            f"{value:g}/{max_value:g}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _cover(report: AuditReport, title: str) -> str:
    ts = datetime.now().isoformat(timespec="seconds")
    return (
        '<header class="cover">'
        f"<h1>{_e(title)}</h1>"
        '<div class="meta">'
        f"<span><strong>Repository:</strong> {_e(report.repo_path)}</span>"
        f"<span><strong>Platform:</strong> {_e(report.platform or 'auto-detected')}</span>"
        f"<span><strong>Generated:</strong> {_e(ts)}</span>"
        "</div></header>"
    )


def _summary(
    report: AuditReport,
    score_report: ScoreReport | None,
    clusters: list[FindingCluster],
) -> str:
    """Executive summary card. Leads with the grade and the distinct-risk
    count so a reader sees the headline numbers before scrolling."""
    parts: list[str] = ['<section aria-labelledby="sum-h"><h2 id="sum-h">Executive summary</h2>']
    parts.append('<div class="summary-card">')
    if score_report is not None:
        grade = score_report.grade
        parts.append(
            f'<div class="grade-box {_grade_class(grade)}">'
            f'<span class="grade">{_e(grade)}</span>'
            f'<span class="score">{_e(score_report.total_score)}/100</span>'
            "</div>"
        )
    else:
        parts.append("<div></div>")

    confirmed = sum(1 for c in clusters if not c.review_needed)
    review = sum(1 for c in clusters if c.review_needed)
    parts.append('<div class="summary-stats">')
    parts.append(_stat(confirmed, "distinct risks"))
    if review:
        parts.append(_stat(review, "review-needed"))
    parts.append(_stat(len(report.findings), "total findings"))
    parts.append(_stat(report.files_scanned, "files scanned"))
    parts.append("</div>")

    sev_bits: list[str] = []
    for sev in Severity:
        c = report.summary.get(sev.value, 0)
        if c:
            sev_bits.append(f"{_severity_badge(sev)} <strong>{_e(c)}</strong>")
    if sev_bits:
        parts.append(f'<div class="summary-counts">{"  ".join(sev_bits)}</div>')

    parts.append("</div></section>")
    return "".join(parts)


def _stat(value: object, label: str) -> str:
    return (
        f'<div class="stat"><div class="num">{_e(value)}</div>'
        f'<div class="lbl">{_e(label)}</div></div>'
    )


def _debt_profile_section(score_report: ScoreReport | None) -> str:
    """Per-family qualitative labels (Strong / Moderate / Weak / Needs review).

    Replaces the implicit "everything is severity-coloured" view with a
    family-aligned scan-line so a reader can see at a glance which axes
    have debt without reading individual findings.
    """
    if score_report is None or not score_report.debt_profile:
        return ""
    rows: list[str] = []
    for d in score_report.debt_profile:
        meta = ""
        if d.finding_count:
            meta = (
                f'<div class="debt-meta">{_e(d.finding_count)} finding(s) &middot; '
                f"expl:{_e(d.top_exploitability)}</div>"
            )
        # Map "Needs review" to a CSS-friendly class.
        label_class = d.label.replace(" ", ".")
        rows.append(
            f'<div class="debt-row">'
            f'<div><div class="debt-name">{_e(d.title)}</div>{meta}</div>'
            f'<div class="debt-label label-{_e(label_class)}">{_e(d.label)}</div>'
            f"</div>"
        )
    return (
        '<section aria-labelledby="debt-h"><h2 id="debt-h">Security debt profile</h2>'
        f'<div class="debt-grid">{"".join(rows)}</div>'
        "</section>"
    )


def _score_section(score_report: ScoreReport) -> str:
    items: list[tuple[str, float, float]] = [
        (c.name, float(c.points), float(c.max_points)) for c in score_report.categories
    ]
    return (
        '<section aria-labelledby="score-h"><h2 id="score-h">Score breakdown</h2>'
        f'<div class="summary-card" style="display:block">{_bar_chart(items)}</div>'
        "</section>"
    )


def _quick_win_section(report: AuditReport) -> str:
    win = _quick_win(report.findings)
    if win is None:
        return ""
    auto = (
        ' <span class="tag">auto-fixable via --fix</span>'
        if win.rule_id in _AUTO_FIXABLE_RULES
        else ""
    )
    first_line = win.remediation.splitlines()[0] if win.remediation else ""
    fix_html = (
        f'<div class="fix"><strong>Fix:</strong> {_e(first_line)}</div>' if first_line else ""
    )
    return (
        '<section><div class="callout">'
        '<div class="callout-label">Quick win</div>'
        f"<div>{_severity_badge(win.severity)} "
        f'<a href="#rule-{_e(win.rule_id)}"><code>{_e(win.rule_id)}</code></a>: '
        f"{_e(win.title)}{auto}</div>"
        f'<div class="fix"><strong>Location:</strong> '
        f"<code>{_e(_relpath_for_display(win.file, report.repo_path))}:{_e(win.line)}</code></div>"
        f"{fix_html}"
        "</div></section>"
    )


def _cluster_card(cluster: FindingCluster, repo_path: str = "") -> str:
    """One root-cause cluster card.

    Uses native ``<details>``/``<summary>`` so the card expands without any
    JavaScript dependency. The summary line carries the severity, exploit-
    ability marker, family title, and finding/file counts. The body shows
    the family description, the contributing rule IDs, and a compact table
    of one row per finding.
    """
    worst = max(cluster.findings, key=lambda f: f.severity.rank)
    sev = worst.severity
    expl = cluster.top_exploitability

    extra_class = ""
    if cluster.review_needed:
        extra_class = " review-needed"

    rules_str = ", ".join(
        f'<a href="#rule-{_e(rid)}"><code>{_e(rid)}</code></a>'
        for rid in sorted(cluster.rule_ids)
    )

    rows: list[str] = []
    sorted_findings = sorted(cluster.findings, key=lambda f: (f.file, f.line))
    # Loop form kept: the multi-line HTML template below reads far
    # better than a nested list-comprehension expression.
    for f in sorted_findings:
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(f.severity)}</td>"
            f'<td><a href="#rule-{_e(f.rule_id)}"><code>{_e(f.rule_id)}</code></a></td>'
            f'<td class="file">{_e(_relpath_for_display(f.file, repo_path))}:{_e(f.line)}</td>'
            f"<td>{_e(f.title)}</td>"
            "</tr>"
        )

    findings_table = (
        '<table class="cluster-findings">'
        "<thead><tr><th>Sev</th><th>Rule</th><th>Location</th><th>Title</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )

    why_html = f'<p class="why">{_e(cluster.why)}</p>' if cluster.why else ""

    n = len(cluster.findings)
    nf = len(cluster.affected_files)
    # n / nf are integers so do not need HTML-escaping; the separator is
    # written as the HTML entity `&middot;` rather than the raw U+00B7
    # glyph so the entire document stays pure ASCII. Raw U+00B7 would
    # otherwise surface as the mojibake "Â·" when the HTML is piped
    # through Windows PowerShell (which re-decodes UTF-8 bytes via
    # cp1252 on its way to `Out-File`).
    counts_html = f"{n} finding{'s' if n != 1 else ''} &middot; {nf} file{'s' if nf != 1 else ''}"

    return (
        f'<details class="cluster sev-card-{sev.value}{extra_class}">'
        "<summary>"
        f"<span>{_severity_badge(sev)}{_expl_badge(expl)}</span>"
        f'<span class="cluster-title">{_e(cluster.title)}</span>'
        f'<span class="cluster-counts">{counts_html}</span>'
        "</summary>"
        '<div class="cluster-body">'
        f"{why_html}"
        f'<div class="rule-ids">Rules: {rules_str}</div>'
        f"{findings_table}"
        "</div></details>"
    )


def _clusters_section(
    clusters: list[FindingCluster],
    heading: str,
    section_id: str,
    only_review: bool,
    repo_path: str = "",
) -> str:
    relevant = [c for c in clusters if c.review_needed == only_review]
    if not relevant:
        return ""
    cards = "".join(_cluster_card(c, repo_path) for c in relevant)
    return (
        f'<section aria-labelledby="{section_id}">'
        f'<h2 id="{section_id}">{_e(heading)} ({len(relevant)})</h2>'
        f"{cards}"
        "</section>"
    )


def _rule_reference_section(report: AuditReport) -> str:
    """Per-rule reference appendix.

    Renders one collapsed ``<details>`` block per unique rule that
    fired, anchored at ``id="rule-<RULE_ID>"`` so cluster headers and
    table rows can link back here.  The block holds the rule's
    title, description, and (when present) remediation text — taken
    from the first finding for that rule, since every finding for
    the same rule shares the same metadata.
    """
    if not report.findings:
        return ""

    # Deduplicate while preserving the first occurrence's metadata.
    seen: dict[str, "Finding"] = {}  # noqa: F821 — quoted for forward use
    for f in report.findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = f

    if not seen:
        return ""

    blocks: list[str] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        body_parts: list[str] = []
        if f.description:
            body_parts.append(f'<p class="rule-desc">{_e(f.description)}</p>')
        if f.remediation:
            body_parts.append(
                '<p class="rule-remediation"><strong>Fix:</strong> '
                f"<code>{_e(f.remediation)}</code></p>"
            )
        if f.reference:
            # Render reference URL as plain text rather than a
            # clickable href.  The HTML report's zero-dependency
            # promise (test_no_external_resource_links) prohibits
            # ``href="http..."`` so the document never gestures at
            # outbound traffic on render.  Users copy the URL.
            body_parts.append(
                f'<p class="rule-ref">Reference: <code>{_e(f.reference)}</code></p>'
            )
        body_html = "".join(body_parts) or "<p>(no further reference)</p>"

        blocks.append(
            f'<details class="rule-ref-block" id="rule-{_e(rule_id)}">'
            f"<summary><code>{_e(rule_id)}</code> &mdash; {_e(f.title)}</summary>"
            f'<div class="rule-ref-body">{body_html}</div>'
            "</details>"
        )

    return (
        '<section aria-labelledby="rules-h">'
        '<h2 id="rules-h">Rule reference</h2>'
        f"{''.join(blocks)}"
        "</section>"
    )


def _flat_findings_section(report: AuditReport) -> str:
    """Supplemental flat table, collapsed by default.

    Some users (auditors, compliance reviewers) want to see every finding
    in one sortable list. The cluster view is the primary surface; this
    is a hidden fallback so they don't lose that view.
    """
    if not report.findings:
        return (
            '<section aria-labelledby="f-h"><h2 id="f-h">All findings</h2>'
            '<p style="color:var(--muted)">No findings.</p>'
            "</section>"
        )
    sorted_findings = sorted(report.findings, key=lambda f: -f.severity.rank)
    rows: list[str] = []
    # Loop-form readability beats list-comp here (multi-line HTML).
    for f in sorted_findings:
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(f.severity)}</td>"
            f'<td><a href="#rule-{_e(f.rule_id)}"><code>{_e(f.rule_id)}</code></a></td>'
            f"<td><code>{_e(_relpath_for_display(f.file, report.repo_path))}:{_e(f.line)}</code></td>"
            f"<td>{_e(f.title)}</td>"
            "</tr>"
        )
    return (
        '<section aria-labelledby="f-h"><h2 id="f-h">'
        f"All findings ({len(sorted_findings)})</h2>"
        '<details><summary style="cursor:pointer; color:var(--muted); padding:6px 0">'
        "Show flat list of every finding</summary>"
        '<table class="flat-table" style="margin-top:8px">'
        "<thead><tr><th>Sev</th><th>Rule</th><th>Location</th><th>Title</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</details></section>"
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def format_html(
    report: AuditReport,
    score_report: ScoreReport | None = None,
    title: str | None = None,
) -> str:
    """Render ``report`` as a complete, self-contained HTML document."""
    if not report.summary:
        report.summarize()
    heading = title or "TAINTLY REPORT"

    clusters = cluster_findings(report.findings) if report.findings else []

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>{_e(heading)}</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body><main>")
    parts.append(_cover(report, heading))
    parts.append(_summary(report, score_report, clusters))
    parts.append(_debt_profile_section(score_report))
    if score_report is not None:
        parts.append(_score_section(score_report))
    parts.append(_quick_win_section(report))
    parts.append(
        _clusters_section(
            clusters,
            "Top distinct risks",
            "risks-h",
            only_review=False,
            repo_path=report.repo_path,
        )
    )
    parts.append(
        _clusters_section(
            clusters,
            "Review-needed patterns",
            "review-h",
            only_review=True,
            repo_path=report.repo_path,
        )
    )
    parts.append(_flat_findings_section(report))
    parts.append(_rule_reference_section(report))
    parts.append(
        "<footer>Generated by taintly &mdash; zero-dependency CI/CD "
        "security scanner. No data was sent to any external service.</footer>"
    )
    parts.append("</main></body></html>")
    html_doc = "".join(parts)

    # Force the entire document to pure 7-bit ASCII by turning any remaining
    # non-ASCII code points (typically em-dashes / smart quotes introduced
    # via rule-authored titles or descriptions) into numeric character
    # references ("&#8212;", "&#183;", ...).  Rationale:
    #
    # Running `taintly --format html > report.html` on Windows PowerShell
    # pipes the UTF-8 bytes we write through ``[Console]::OutputEncoding``
    # (cp1252 on most setups).  Any multi-byte UTF-8 sequence then becomes
    # two or three cp1252 code points, so an em-dash surfaces as the
    # familiar "â€"" mojibake, middle-dot as "Â·", and so on.  Once the
    # output is pure ASCII every byte round-trips through cp1252 unchanged,
    # and the browser decodes the numeric entities back to the original
    # glyph via the <meta charset="utf-8"> in the document head.
    #
    # We don't lose the glyph — just change how it's carried across the
    # pipe.
    return html_doc.encode("ascii", "xmlcharrefreplace").decode("ascii")
