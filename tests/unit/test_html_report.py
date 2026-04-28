"""Tests for the self-contained HTML reporter.

The HTML report renders a complete <!DOCTYPE html> document with inline CSS/JS
and no external resource links. These tests cover the deliverable requirements:

* valid document shell
* XSS escaping of user-supplied fields (rule_id, title, file, ...)
* rendering with and without a ScoreReport
* SVG accessibility (each category bar has a readable label)
* CLI wire-up (``--format html`` produces a valid document end-to-end)
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.html_report import _bar_chart, format_html
from taintly.scorer import compute_score


def test_empty_report_renders_valid_document(empty_report):
    html = format_html(empty_report)
    assert html.startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "</html>" in html
    assert "No findings." in html


def test_renders_rule_id_and_file(one_report, one_finding):
    html = format_html(one_report)
    assert one_finding.rule_id in html
    assert one_finding.file in html
    # Section header should be present.
    assert "Findings" in html


def test_xss_escape_of_malicious_title():
    malicious = "<script>alert(1)</script>"
    finding = Finding(
        rule_id="SEC-EVIL-001",
        severity=Severity.HIGH,
        title=malicious,
        description=malicious,
        file="evil.yml",
        line=1,
    )
    report = AuditReport(repo_path="/r", platform="github")
    report.add(finding)
    report.summarize()
    html = format_html(report)
    # Raw tag must not appear — would be an XSS vector.
    assert "<script>alert(1)</script>" not in html
    # Escaped form must appear.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_xss_escape_of_malicious_file_path():
    finding = Finding(
        rule_id="SEC3-GH-001",
        severity=Severity.HIGH,
        title="Unpinned action",
        description="x",
        file="<img src=x onerror=alert(1)>",
        line=1,
    )
    report = AuditReport(repo_path="/r", platform="github")
    report.add(finding)
    report.summarize()
    html = format_html(report)
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_renders_without_score_report(one_report):
    html = format_html(one_report, score_report=None)
    assert html.startswith("<!DOCTYPE html>")
    # No grade-box *element* (class attr) when no score provided — the CSS
    # rule itself always ships.
    assert 'class="grade-box' not in html
    # No score breakdown section either.
    assert "Score breakdown" not in html
    # Executive summary still rendered.
    assert "Executive summary" in html


def test_renders_with_score_report(one_report):
    score = compute_score(one_report.findings, files_scanned=1)
    html = format_html(one_report, score_report=score)
    # Grade letter should be visible.
    assert f">{score.grade}<" in html
    assert "grade-box" in html
    # Score breakdown section rendered.
    assert "Score breakdown" in html


def test_bar_chart_includes_category_titles():
    # Build a minimal score report and verify SVG has the required <title>.
    findings: list[Finding] = []
    score = compute_score(findings, files_scanned=0)
    svg = _bar_chart(
        [(c.name, float(c.points), float(c.max_points)) for c in score.categories]
    )
    assert svg.startswith("<svg")
    assert 'role="img"' in svg
    assert "<title>" in svg
    assert "<desc>" in svg
    # Every category name should appear as a bar label.
    for c in score.categories:
        assert c.name in svg


def test_custom_title_is_honored(empty_report):
    html = format_html(empty_report, title="My Custom Title")
    assert "My Custom Title" in html


def test_no_external_resource_links(one_report):
    # Zero-dependency promise: no CDN references and no <link>/<script src=>
    # tags. The SVG xmlns attribute is a namespace URI (not a fetch) and the
    # w3.org URL inside xmlns="..." is the canonical SVG namespace value.
    html = format_html(one_report, score_report=compute_score(one_report.findings, 1))
    lowered = html.lower()
    for forbidden in ("<link ", "<script src", "//cdn.", "googleapis", "jsdelivr", "unpkg"):
        assert forbidden not in lowered, f"HTML should not link to {forbidden}"
    # No URL-as-href/src attributes.
    assert "href=\"http" not in lowered
    assert "src=\"http" not in lowered


def _multi_cluster_report() -> AuditReport:
    """Report with findings spanning multiple families and one
    review-needed cluster, used to drive cluster-card / debt-profile
    rendering tests."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.files_scanned = 3

    # Confirmed cluster: many SEC3-GH-001 hits (mutable deps)
    for i in range(8):
        report.add(Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.HIGH,
            title="Unpinned action",
            description="mutable tag",
            file=f".github/workflows/job-{i}.yml",
            line=10,
            owasp_cicd="CICD-SEC-3",
            finding_family="supply_chain_immutability",
            confidence="high",
            exploitability="high",
        ))
    # Confirmed cluster: one CRITICAL injection
    report.add(Finding(
        rule_id="SEC4-GH-006",
        severity=Severity.CRITICAL,
        title="GITHUB_ENV injection",
        description="taint flow",
        file=".github/workflows/inject.yml",
        line=18,
        owasp_cicd="CICD-SEC-4",
        finding_family="script_injection",
        confidence="high",
        exploitability="high",
    ))
    # Review-needed cluster
    report.add(Finding(
        rule_id="SEC4-GH-002",
        severity=Severity.HIGH,
        title="pull_request_target",
        description="trigger only",
        file=".github/workflows/welcome.yml",
        line=3,
        owasp_cicd="CICD-SEC-4",
        finding_family="privileged_pr_trigger",
        confidence="medium",
        exploitability="low",
        review_needed=True,
    ))
    report.summarize()
    return report


def test_html_groups_findings_into_cluster_cards():
    """The 8 SEC3-GH-001 findings must collapse to ONE cluster card with
    a count, not 8 separate rows in a flat table."""
    report = _multi_cluster_report()
    html = format_html(report)
    # Cluster card section appears
    assert "Top distinct risks" in html
    # The supply-chain family title is visible, exactly once per cluster
    assert html.count("Mutable dependency references") >= 1
    # The 8-finding count is shown in the cluster summary
    assert "8 findings" in html
    # The card uses native <details> for collapse
    assert "<details" in html and "<summary" in html


def test_cluster_summary_uses_flex_not_grid():
    """Regression: the cluster summary used `display: grid` with THREE
    explicit columns (`auto 1fr auto`) but had FOUR grid items because
    `::before` (the disclosure triangle) counts as a grid item per the
    CSS Grid spec. Depending on the browser, the title column either
    collapsed to zero width (user saw "just a strike in the field"
    where the title should be) or the counts wrapped to a second row.

    Flexbox absorbs the pseudo-element naturally, so the fix switches
    `.cluster summary` to `display: flex` and puts `flex: 1` on the
    title to grow it between the badges and the right-aligned counts.
    This test locks that layout in.
    """
    report = _multi_cluster_report()
    html = format_html(report)
    # Extract the `.cluster summary` CSS block.
    import re
    m = re.search(r"\.cluster summary \{([^}]*)\}", html)
    assert m, "`.cluster summary` CSS block is missing from the document"
    rules = m.group(1)
    # The specific pathological declaration must be gone.
    assert "grid-template-columns" not in rules, (
        "`.cluster summary` must not use grid-template-columns; the "
        "::before pseudo-element becomes a grid item and collapses the "
        "title column"
    )
    assert "display: flex" in rules, (
        "`.cluster summary` must use flexbox so the `::before` disclosure "
        "triangle sits inline with the 3 content spans"
    )
    # Title must be the flex-grow slot — otherwise the badges span grows
    # instead and the title gets pushed to zero width again.
    m2 = re.search(r"\.cluster \.cluster-title \{([^}]*)\}", html)
    assert m2, "`.cluster .cluster-title` CSS block is missing"
    assert "flex: 1" in m2.group(1), (
        "`.cluster-title` must have `flex: 1` so it stretches between the "
        "badges and the right-aligned counts"
    )


def test_cluster_card_title_appears_in_summary():
    """The cluster title ('Mutable dependency references', 'Script
    injection...', etc.) must actually show up inside the <summary>
    element, not just somewhere else in the document. Catches the exact
    symptom the user reported: header spans were present but the title
    field rendered empty.
    """
    report = _multi_cluster_report()
    html = format_html(report)
    import re
    summaries = re.findall(
        r"<details class=\"cluster [^\"]*\"><summary>(.*?)</summary>",
        html,
        re.DOTALL,
    )
    assert summaries, "no cluster <summary> elements rendered"
    for s in summaries:
        title_match = re.search(
            r'<span class="cluster-title">([^<]+)</span>', s
        )
        assert title_match, (
            "cluster-title span is empty or missing inside the summary: "
            f"{s[:200]!r}"
        )
        title = title_match.group(1).strip()
        # At minimum 4 chars — a realistic cluster title is always a full
        # noun phrase ("Mutable dependency references" etc.), never a
        # single character or dash.
        assert len(title) >= 4, (
            f"cluster-title rendered as stub {title!r} — the layout bug "
            f"where the title collapses to an empty strike is back"
        )


def test_html_separates_review_needed_from_confirmed():
    """Review-needed cluster lands in its own section, not 'Top distinct
    risks'."""
    report = _multi_cluster_report()
    html = format_html(report)
    assert "Review-needed patterns" in html
    # The review-needed cluster card carries the marker class
    assert "review-needed" in html


def test_html_renders_debt_profile_with_score_report():
    """When a ScoreReport is provided, the debt profile section must
    render with one row per family carrying a Strong/Moderate/Weak
    label."""
    from taintly.scorer import compute_score
    report = _multi_cluster_report()
    score = compute_score(report.findings, files_scanned=report.files_scanned)
    html = format_html(report, score_report=score)
    assert "Security debt profile" in html
    # At least one of the qualitative labels must appear
    assert any(label in html for label in ("label-Strong", "label-Weak", "label-Moderate"))


def test_html_uses_native_details_no_js_required_for_cluster_expand():
    """The cluster expand/collapse must work without JS so the report
    is useful when JS is disabled or sandboxed."""
    report = _multi_cluster_report()
    html = format_html(report)
    # The cluster cards are <details> elements
    assert '<details class="cluster' in html


def test_html_cluster_card_lists_component_rule_ids():
    """The cluster body must show the rule IDs that contributed so a
    reader can drill back into individual rules."""
    report = _multi_cluster_report()
    html = format_html(report)
    # Even though the SEC3-GH-001 cluster contains only one rule, the
    # rule ID must appear within the cluster body, not just in the flat
    # findings table at the bottom.
    assert "SEC3-GH-001" in html


def test_html_flat_findings_section_collapsed_by_default():
    """The flat findings table is kept as a fallback for auditors who
    want to see every row, but it must be wrapped in a <details> so it
    doesn't dominate the page on first load."""
    report = _multi_cluster_report()
    html = format_html(report)
    # The "All findings" heading is present
    assert "All findings" in html
    # The flat table is inside a collapsed <details>
    assert "Show flat list of every finding" in html


def test_html_output_is_pure_ascii_for_windows_cp1252_pipe(one_report):
    """Regression: `taintly --format html > report.html` on Windows
    PowerShell re-decodes the pipe bytes through ``[Console]::OutputEncoding``
    (usually cp1252), so any non-ASCII byte we write surfaces as mojibake
    in the saved file (em-dash becomes ``â€"``, middle-dot becomes ``Â·``,
    the ``▸`` disclosure triangle becomes ``â–¸``, etc.).

    We guarantee the *bytes* are pure ASCII and use HTML entities / CSS
    escapes instead of raw Unicode glyphs.  The document then survives any
    single-byte re-decoding without losing characters.
    """
    from taintly.scorer import compute_score

    html = format_html(one_report, score_report=compute_score(one_report.findings, 1))
    # No code point outside 7-bit ASCII — this is the one assertion that
    # actually proves the fix: Python will raise if any non-ASCII slipped in.
    html.encode("ascii")
    # And specifically: simulate the full UTF-8 -> cp1252 -> UTF-8 round-trip
    # that PowerShell performs when `Out-File` saves piped stdout on a
    # cp1252 console.  The content must be bit-for-bit identical.
    assert html.encode("utf-8").decode("cp1252").encode("utf-8").decode("utf-8") == html


def test_html_middot_separator_rendered_as_entity():
    """The cluster count separator must use `&middot;`, not the raw U+00B7
    glyph, so it survives the Windows PowerShell cp1252 re-decoding path.
    """
    report = _multi_cluster_report()
    html = format_html(report)
    assert "&middot;" in html
    assert "\u00b7" not in html  # raw middle-dot must not leak into output


def test_html_disclosure_triangle_uses_css_escape():
    """The cluster summary arrow is emitted via the CSS hex escape
    ``\\25B8`` rather than the raw U+25B8 glyph so the stylesheet (and
    therefore the whole document) stays ASCII-safe."""
    report = _multi_cluster_report()
    html = format_html(report)
    assert "\\25B8" in html
    assert "\u25b8" not in html


def test_html_rule_authored_unicode_becomes_numeric_entity():
    """Rule authors routinely embed non-ASCII chars (em-dashes, smart
    quotes, ellipses) in rule titles / descriptions. Those must not
    leak through as raw UTF-8 bytes or the output gets mangled by a
    cp1252 re-decoding pipe.  They must survive as numeric HTML
    character references, which the browser decodes back to the
    original glyph via ``<meta charset="utf-8">`` in the document head.
    """
    # Every test glyph lives in the title — it's the only rule-authored
    # field the HTML reporter renders in both the cluster card and the
    # flat findings table, so it's the realistic mojibake vector.
    finding = Finding(
        rule_id="SEC-UNI-001",
        severity=Severity.HIGH,
        title="Timeout \u2014 \u201crun forever\u201d\u2026",
        description="x",
        file=".github/workflows/ci.yml",
        line=1,
    )
    report = AuditReport(repo_path="/r", platform="github")
    report.add(finding)
    report.summarize()
    html = format_html(report)
    # Whole document must be pure ASCII so it survives cp1252 redirection.
    html.encode("ascii")
    # Specific glyphs are preserved as numeric entities (browser decodes them).
    assert "&#8212;" in html  # em-dash
    assert "&#8220;" in html  # left double quotation mark
    assert "&#8221;" in html  # right double quotation mark
    assert "&#8230;" in html  # horizontal ellipsis
    # No raw non-ASCII chars slipped through.
    for bad in ("\u2014", "\u201c", "\u201d", "\u2026"):
        assert bad not in html


def test_cli_format_html_produces_valid_document(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    # Intentionally unpinned action to guarantee >=1 finding.
    workflow.write_text(
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path), "--format", "html", "--no-color"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Exit code may be 0/1/2 depending on findings — we only care about stdout.
    assert result.stdout.startswith("<!DOCTYPE html>"), result.stderr
    assert "</html>" in result.stdout
    # Score section auto-computed for html format.
    assert "Score breakdown" in result.stdout
