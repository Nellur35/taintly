"""Unit tests for all four output reporters.

The highest-priority gap from the reasoning pipeline: SARIF output was never
validated. A malformed SARIF causes GitHub Advanced Security to silently discard
the upload — producing zero findings in the dashboard while the tool exits 0.

Tests verify:
- SARIF: correct schema fields, version string, no duplicate artifacts
- JSON: parseable, required keys present, finding fields correct
- CSV: headers present, values not corrupted by special chars
- Text: no ANSI codes in --no-color mode, rule ID appears in output
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.csv_report import format_csv
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif
from taintly.reporters.text import format_text

# =============================================================================
# SARIF
# =============================================================================


def test_sarif_version_is_correct_string(one_report):
    """SARIF requires version = "2.1.0" (not "2.1", not None)."""
    sarif = json.loads(format_sarif(one_report))
    assert sarif["version"] == "2.1.0", (
        f"SARIF version must be '2.1.0', got {sarif['version']!r}. "
        "GitHub Advanced Security will silently reject any other value."
    )


def test_sarif_driver_version_matches_package_version(one_report):
    """The tool.driver.version field must reflect the installed taintly
    version, not a hardcoded literal.  A reviewer running v1.x.y on a
    SARIF triage tool should see ``1.x.y`` in the tool record, not the
    ``0.0.0`` placeholder this code shipped with at one point."""
    from taintly import __version__

    sarif = json.loads(format_sarif(one_report))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__, (
        f"SARIF tool.driver.version must equal taintly.__version__ "
        f"({__version__!r}), got {driver['version']!r}."
    )


def test_sarif_has_schema_field(one_report):
    sarif = json.loads(format_sarif(one_report))
    assert "$schema" in sarif


def test_sarif_runs_structure(one_report):
    sarif = json.loads(format_sarif(one_report))
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert "driver" in run["tool"]


def test_sarif_result_has_required_fields(one_report):
    sarif = json.loads(format_sarif(one_report))
    result = sarif["runs"][0]["results"][0]
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "locations" in result
    assert result["ruleId"] == "SEC3-GH-001"


def test_sarif_location_has_uri_and_line(one_report):
    sarif = json.loads(format_sarif(one_report))
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    phys = loc["physicalLocation"]
    assert "artifactLocation" in phys
    assert "uri" in phys["artifactLocation"]
    assert "region" in phys
    assert phys["region"]["startLine"] >= 1


def test_sarif_level_mapping(one_report):
    """HIGH severity must map to 'error', not 'warning' or 'note'."""
    sarif = json.loads(format_sarif(one_report))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error", (
        f"HIGH severity should map to SARIF level 'error', got {result['level']!r}"
    )


def test_sarif_artifacts_deduplicated():
    """artifacts array must have one entry per file, not one per finding."""
    report = AuditReport(repo_path="/repo", platform="github")
    for i in range(3):
        report.add(
            Finding(
                rule_id=f"RULE-{i}",
                severity=Severity.HIGH,
                title="t",
                description="d",
                file=".github/workflows/ci.yml",  # same file, 3 findings
                line=i + 1,
                snippet="",
            )
        )
    report.summarize()
    sarif = json.loads(format_sarif(report))
    artifacts = sarif["runs"][0]["artifacts"]
    uris = [a["location"]["uri"] for a in artifacts]
    assert len(uris) == len(set(uris)), (
        f"SARIF artifacts has {len(uris)} entries for {len(set(uris))} unique files — duplicates present"
    )


def test_sarif_empty_report_is_valid_json(empty_report):
    output = format_sarif(empty_report)
    sarif = json.loads(output)
    assert sarif["runs"][0]["results"] == []


def test_sarif_is_valid_json(one_report):
    output = format_sarif(one_report)
    try:
        json.loads(output)
    except json.JSONDecodeError as e:
        pytest.fail(f"format_sarif produced invalid JSON: {e}")


# =============================================================================
# ENGINE-ERR surfacing (SARIF + JSON + min-severity preservation)
# =============================================================================


def _engine_err_finding(title: str = "Could not read file") -> Finding:
    return Finding(
        rule_id="ENGINE-ERR",
        severity=Severity.LOW,
        title=title,
        description=title,
        file=".github/workflows/broken.yml",
    )


def test_filter_severity_preserves_engine_err():
    """A user running --min-severity HIGH must still see engine errors:
    silent coverage loss is the exact thing this finding signals."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(_engine_err_finding())
    report.add(
        Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.LOW,
            title="real low finding",
            description="x",
            file="a.yml",
        )
    )
    report.filter_severity(Severity.HIGH)
    rule_ids = [f.rule_id for f in report.findings]
    assert "ENGINE-ERR" in rule_ids, (
        "ENGINE-ERR was filtered out by --min-severity HIGH; the user "
        "would silently lose the only signal that scanning failed."
    )
    assert "SEC3-GH-001" not in rule_ids, (
        "Real LOW findings should still be filtered when min-severity=HIGH; "
        "only ENGINE-ERR is exempt."
    )


def test_engine_errors_accessor_returns_only_engine_err():
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(_engine_err_finding())
    report.add(
        Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.HIGH,
            title="real",
            description="x",
            file="a.yml",
        )
    )
    errs = report.engine_errors()
    assert len(errs) == 1
    assert errs[0].rule_id == "ENGINE-ERR"


def test_json_includes_top_level_errors_field():
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(_engine_err_finding("ReDoS cap hit"))
    report.summarize()

    data = json.loads(format_json(report))
    assert "errors" in data, "JSON must expose ENGINE-ERR via top-level 'errors' field."
    assert len(data["errors"]) == 1
    assert data["errors"][0]["rule_id"] == "ENGINE-ERR"
    assert data["errors"][0]["title"] == "ReDoS cap hit"


def test_engine_err_printed_to_stderr_regardless_of_min_severity(capsys):
    """The stderr channel for engine errors is the only thing visible
    to a user running --min-severity HIGH; regression guard."""
    from taintly.__main__ import _print_engine_errors_to_stderr

    report = AuditReport(repo_path="/repo", platform="github")
    report.add(_engine_err_finding("Rule SEC3-GH-001 failed: timeout"))
    report.summarize()

    _print_engine_errors_to_stderr(report)
    captured = capsys.readouterr()
    assert "engine error" in captured.err
    assert "Rule SEC3-GH-001 failed: timeout" in captured.err
    assert captured.out == "", "engine errors must go to stderr, not stdout"


def test_sarif_engine_err_appears_in_tool_execution_notifications():
    """SARIF spec §3.58 puts runtime tool events in
    invocations[*].toolExecutionNotifications, separate from results."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(_engine_err_finding("File too large"))
    report.summarize()

    sarif = json.loads(format_sarif(report))
    invocations = sarif["runs"][0]["invocations"]
    assert len(invocations) == 1
    notifications = invocations[0]["toolExecutionNotifications"]
    assert len(notifications) == 1, (
        "ENGINE-ERR must be mirrored into "
        "invocations[*].toolExecutionNotifications so SARIF consumers "
        "see engine errors without grepping rule IDs."
    )
    note = notifications[0]
    assert note["descriptor"]["id"] == "ENGINE-ERR"
    assert note["message"]["text"] == "File too large"


# =============================================================================
# JSON reporter
# =============================================================================


def test_json_output_is_valid_json(one_report):
    output = format_json(one_report)
    try:
        json.loads(output)
    except json.JSONDecodeError as e:
        pytest.fail(f"format_json produced invalid JSON: {e}")


def test_json_top_level_keys(one_report):
    data = json.loads(format_json(one_report))
    for key in ("repo_path", "platform", "files_scanned", "summary", "findings"):
        assert key in data, f"Missing top-level key: {key!r}"


def test_json_finding_fields(one_report):
    data = json.loads(format_json(one_report))
    finding = data["findings"][0]
    for key in ("rule_id", "severity", "title", "description", "file", "line"):
        assert key in finding, f"Missing finding field: {key!r}"
    assert finding["rule_id"] == "SEC3-GH-001"
    assert finding["severity"] == "HIGH"
    assert finding["line"] == 12


def test_json_empty_report(empty_report):
    data = json.loads(format_json(empty_report))
    assert data["findings"] == []
    assert data["summary"]["total"] == 0


# =============================================================================
# CSV reporter
# =============================================================================


def test_csv_has_headers(one_report):
    output = format_csv(one_report)
    reader = csv.DictReader(io.StringIO(output))
    headers = reader.fieldnames or []
    for expected in ("rule_id", "severity", "file", "line"):
        assert expected in headers, f"CSV missing header: {expected!r}"


def test_csv_finding_values(one_report):
    output = format_csv(one_report)
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "SEC3-GH-001"
    assert rows[0]["severity"] == "HIGH"


def test_csv_special_chars_dont_corrupt(tmp_path):
    """A finding with commas and quotes in the snippet must not break CSV parsing."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="SEC4-GH-004",
            severity=Severity.HIGH,
            title="Injection: ${{ github.event.pull_request.title }}",
            description='Context "title" used directly in run:',
            file=".github/workflows/ci.yml",
            line=5,
            snippet='run: echo "${{ github.event.pull_request.title }}"',
        )
    )
    report.summarize()
    output = format_csv(report)
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "SEC4-GH-004"


# =============================================================================
# Text reporter
# =============================================================================


def test_text_no_color_has_no_ansi_codes(one_report):
    output = format_text(one_report, use_color=False)
    assert "\033[" not in output, "format_text(use_color=False) must not contain ANSI escape codes"


def test_text_contains_rule_id(one_report):
    output = format_text(one_report, use_color=False)
    assert "SEC3-GH-001" in output


def test_text_contains_file_path(one_report):
    output = format_text(one_report, use_color=False)
    assert ".github/workflows/ci.yml" in output


def test_text_empty_report_does_not_crash(empty_report):
    output = format_text(empty_report, use_color=False)
    assert isinstance(output, str)


# =============================================================================
# Executive summary (score, top issues, top risk, quick win)
# =============================================================================


def _multi_finding_report():
    report = AuditReport(repo_path="/repo", platform="github")
    report.files_scanned = 2
    # Two auto-fixable findings (SEC3-GH-001) plus one CRITICAL non-fixable
    for i in range(2):
        report.add(
            Finding(
                rule_id="SEC3-GH-001",
                severity=Severity.HIGH,
                title="Unpinned action",
                description="mutable tag",
                file=".github/workflows/a.yml",
                line=10 + i,
                remediation="Pin to full 40-char commit SHA",
                owasp_cicd="CICD-SEC-3",
            )
        )
    report.add(
        Finding(
            rule_id="SEC4-GH-002",
            severity=Severity.CRITICAL,
            title="pull_request_target with checkout",
            description="PPE",
            file=".github/workflows/a.yml",
            line=2,
            remediation="Use pull_request trigger",
            owasp_cicd="CICD-SEC-4",
        )
    )
    report.summarize()
    return report


def test_text_summary_includes_files_and_totals():
    report = _multi_finding_report()
    output = format_text(report, use_color=False)
    assert "Files scanned:  2" in output
    assert "Total findings: 3" in output


def test_text_top_issues_groups_by_rule_id():
    report = _multi_finding_report()
    output = format_text(report, use_color=False)
    # SEC3-GH-001 fired twice — should appear in Top 3 with "2 findings"
    assert "Top 3 issues" in output
    assert "2 findings" in output


def test_text_top_risk_picks_highest_severity():
    report = _multi_finding_report()
    output = format_text(report, use_color=False)
    top_risk_section = output.split("Top risk")[1].split("Quick win")[0]
    assert "CRITICAL" in top_risk_section
    assert "SEC4-GH-002" in top_risk_section


def test_text_top_risk_prefers_confirmed_over_review_needed_at_same_severity():
    """Two HIGH findings — one confirmed-risk (review_needed=False),
    one analyst-review (review_needed=True).  The confirmed-risk
    finding must surface as the top risk despite same severity rank.

    Locks in the surface-priority sort key:
        (severity, not_review_needed, confidence_rank).
    Without the review_needed tier, the first occurrence in iteration
    order would win ties — which is the wrong UX for a
    confirmed-vs-review distinction.
    """
    from taintly.reporters.text import _top_risk

    review_needed = Finding(
        rule_id="XF-GH-001",
        severity=Severity.HIGH,
        title="generic cache poisoning (review)",
        description="x",
        file=".github/workflows/a.yml",
        confidence="medium",
        review_needed=True,
    )
    confirmed = Finding(
        rule_id="XF-GH-001A",
        severity=Severity.HIGH,
        title="executable-cache poisoning",
        description="x",
        file=".github/workflows/b.yml",
        confidence="high",
        review_needed=False,
    )
    # The review_needed finding appears FIRST in iteration order so we
    # know any sort that keeps insertion order ties would pick it.
    top = _top_risk([review_needed, confirmed])
    assert top is not None
    assert top.rule_id == "XF-GH-001A", (
        f"top-risk picked {top.rule_id} but should have preferred the "
        "confirmed-risk XF-GH-001A over the review_needed XF-GH-001 at "
        "the same severity rank"
    )


def test_text_top_risk_prefers_high_confidence_within_same_review_tier():
    """At same severity AND same review_needed, higher confidence wins."""
    from taintly.reporters.text import _top_risk

    medium_conf = Finding(
        rule_id="A",
        severity=Severity.HIGH,
        title="medium",
        description="x",
        file="a.yml",
        confidence="medium",
        review_needed=False,
    )
    high_conf = Finding(
        rule_id="B",
        severity=Severity.HIGH,
        title="high",
        description="x",
        file="b.yml",
        confidence="high",
        review_needed=False,
    )
    assert _top_risk([medium_conf, high_conf]).rule_id == "B"


def test_text_quick_win_prefers_auto_fixable_rule():
    report = _multi_finding_report()
    output = format_text(report, use_color=False)
    # Header separator is ASCII '=' because format_text() transliterates
    # its final output to 7-bit ASCII (rule-authored em-dashes / box-drawing
    # would otherwise mojibake through cp1252 pipes on Windows).
    quick_win_section = output.split("Quick win")[1].split("=== Findings")[0]
    # SEC3-GH-001 is auto-fixable; CRITICAL SEC4-GH-002 is not
    assert "SEC3-GH-001" in quick_win_section
    assert "auto-fixable via --fix" in quick_win_section


def test_text_includes_score_when_passed():
    from taintly.scorer import compute_score

    report = _multi_finding_report()
    score = compute_score(report.findings, files_scanned=report.files_scanned)
    output = format_text(report, use_color=False, score_report=score)
    assert f"Score:          {score.total_score}/100 ({score.grade})" in output


def test_text_score_omitted_when_not_passed():
    report = _multi_finding_report()
    output = format_text(report, use_color=False)
    assert "Score:" not in output


# =============================================================================
# Reporter v2 — Top distinct risks block
# =============================================================================


def _v2_multi_family_report():
    """Report containing findings from two distinct root-cause families.

    The text reporter should cluster these into two distinct risks with
    the stronger cluster (higher severity) ranked first.
    """
    from taintly.families import classify_rule, default_confidence, default_review_needed

    report = AuditReport(repo_path="/repo", platform="github")
    report.files_scanned = 2

    def _add(rule_id, severity, owasp, file_, line):
        report.add(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=f"{rule_id} fired",
                description="",
                file=file_,
                line=line,
                owasp_cicd=owasp,
                finding_family=classify_rule(rule_id, owasp),
                confidence=default_confidence(rule_id),
                review_needed=default_review_needed(rule_id),
            )
        )

    # Two findings in the supply-chain family — should cluster
    _add("SEC3-GH-001", Severity.HIGH, "CICD-SEC-3", ".github/workflows/a.yml", 10)
    _add("SEC3-GH-002", Severity.CRITICAL, "CICD-SEC-3", ".github/workflows/a.yml", 20)
    # One injection-family finding
    _add("SEC4-GH-006", Severity.CRITICAL, "CICD-SEC-4", ".github/workflows/b.yml", 5)
    report.summarize()
    return report


def test_text_shows_top_distinct_risks_block():
    """The report must include the v2 'Top distinct risks' heading."""
    report = _v2_multi_family_report()
    output = format_text(report, use_color=False)
    assert "Top distinct risks" in output


def test_text_clusters_correlated_rules_into_one_risk():
    """The two SEC3 findings must appear as one cluster in the block."""
    report = _v2_multi_family_report()
    output = format_text(report, use_color=False)
    # Extract the section
    section = output.split("Top distinct risks")[1].split("Top 3 issues")[0]
    assert "Mutable dependency references" in section
    # 2 findings from the SEC3 family across 1 file
    assert "2 findings across 1 file" in section


def test_text_distinct_risk_count_in_summary():
    """The summary line should expose the distinct-risk count."""
    report = _v2_multi_family_report()
    output = format_text(report, use_color=False)
    # Two distinct confirmed risks (supply-chain + script injection)
    assert "Distinct risks: 2 confirmed" in output


def test_text_finding_list_shows_confidence_marker_for_medium():
    """Findings below 'high' confidence must be labelled in the list."""
    from taintly.families import default_confidence

    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="TAINT-GH-001",
            severity=Severity.HIGH,
            title="Shallow taint",
            description="",
            file=".github/workflows/a.yml",
            line=1,
            finding_family="script_injection",
            confidence=default_confidence("TAINT-GH-001"),  # medium
        )
    )
    report.summarize()
    output = format_text(report, use_color=False)
    assert "confidence:medium" in output


# =============================================================================
# Reporter v2 — JSON includes families + confidence
# =============================================================================


def test_json_output_includes_families_summary():
    report = _v2_multi_family_report()
    data = json.loads(format_json(report))
    assert "families" in data
    assert "distinct_risk_count" in data
    assert data["distinct_risk_count"] == 2
    family_ids = {fam["family_id"] for fam in data["families"]}
    assert "supply_chain_immutability" in family_ids
    assert "script_injection" in family_ids


def test_json_finding_includes_confidence_and_family():
    report = _v2_multi_family_report()
    data = json.loads(format_json(report))
    finding = data["findings"][0]
    assert "finding_family" in finding
    assert "confidence" in finding
    assert "review_needed" in finding
    assert "exploitability" in finding


# =============================================================================
# SARIF — v2 metadata fields must surface in result.properties
# =============================================================================


def test_sarif_result_carries_v2_properties():
    """GitHub/GitLab dashboards preserve result.properties — the new
    v2 fields must travel there so downstream dashboards can filter
    on finding_family / confidence / exploitability without custom
    parsing of description strings."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.HIGH,
            title="Unpinned action",
            description="",
            file=".github/workflows/a.yml",
            line=10,
            finding_family="supply_chain_immutability",
            confidence="medium",
            exploitability="high",
            review_needed=False,
        )
    )
    report.summarize()
    sarif = json.loads(format_sarif(report))
    result = sarif["runs"][0]["results"][0]
    assert "properties" in result
    props = result["properties"]
    assert props["finding_family"] == "supply_chain_immutability"
    assert props["confidence"] == "medium"
    assert props["exploitability"] == "high"


# =============================================================================
# Repeat-collapse in the text reporter (review feedback fix)
# =============================================================================


def _many_findings_one_rule(n: int) -> AuditReport:
    """Report with n findings of the same rule across n distinct files —
    the gitlabhq scenario the reviewer flagged as 'painful to scroll'."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.files_scanned = n
    for i in range(n):
        report.add(
            Finding(
                rule_id="SEC3-GH-001",
                severity=Severity.HIGH,
                title="Unpinned action",
                description="mutable tag",
                file=f".github/workflows/job-{i:03d}.yml",
                line=10,
                snippet="- uses: actions/checkout@v4",
                remediation="Pin to a full SHA.",
                owasp_cicd="CICD-SEC-3",
                finding_family="supply_chain_immutability",
                confidence="high",
                exploitability="medium",
            )
        )
    report.summarize()
    return report


def test_text_collapses_repeated_rule_above_threshold():
    """A rule firing 12 times should collapse to one summary block."""
    report = _many_findings_one_rule(12)
    output = format_text(report, use_color=False)
    # Summary line must mention the count and unique file count
    assert "12 instances across 12 file(s)" in output
    # The full per-finding "File: " repetition should NOT appear 12 times
    assert output.count("    File: ") <= 1, (
        "Collapsed group should show one 'File:' (the sample), not 12"
    )


def test_text_does_not_collapse_below_threshold():
    """5 or fewer instances of a rule still render individually."""
    report = _many_findings_one_rule(4)
    output = format_text(report, use_color=False)
    # Each finding should render its own File: line
    assert output.count("    File: ") == 4
    assert "instances across" not in output


def test_text_verbose_disables_collapse():
    """--verbose (verbose=True) must expand every finding."""
    report = _many_findings_one_rule(12)
    output = format_text(report, use_color=False, verbose=True)
    # Verbose mode shows every finding individually
    assert output.count("    File: ") == 12
    assert "instances across" not in output


def test_text_collapse_hint_printed():
    """Footer must point users at --verbose when collapse happened."""
    report = _many_findings_one_rule(12)
    output = format_text(report, use_color=False)
    assert "--verbose" in output


# =============================================================================
# Project-scope dedup (review feedback fix)
# =============================================================================


def test_project_scope_rules_deduped_in_scan_repo(tmp_path):
    """SEC10-GL-002 should fire once per scan, not once per CI file.

    Drives the engine end-to-end so the dedup actually takes effect
    where it matters (scan_repo), not just in isolation.
    """
    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_all_rules

    # Build a fake GitLab repo with three CI files
    (tmp_path / ".gitlab-ci.yml").write_text("stages:\n  - build\n", encoding="utf-8")
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "lint.yml").write_text("lint:\n  script: echo lint\n", encoding="utf-8")
    (tmp_path / "ci" / "build.yml").write_text("build:\n  script: echo build\n", encoding="utf-8")

    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, platform=Platform.GITLAB)
    assert reports, "scan should produce a report"
    sec10_count = sum(
        1 for report in reports for f in report.findings if f.rule_id == "SEC10-GL-002"
    )
    assert sec10_count == 1, (
        f"SEC10-GL-002 should fire once per project, got {sec10_count} instances"
    )


def test_sarif_review_needed_flag_surfaces_when_set():
    """Review-needed must be present and True for review-needed
    findings, and absent otherwise — keeps the SARIF output lean for
    the common case."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="SEC4-GH-002",
            severity=Severity.HIGH,
            title="pull_request_target",
            description="",
            file=".github/workflows/x.yml",
            line=3,
            finding_family="privileged_pr_trigger",
            confidence="medium",
            exploitability="medium",
            review_needed=True,
        )
    )
    report.summarize()
    sarif = json.loads(format_sarif(report))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("review_needed") is True


# =============================================================================
# Encoding fallbacks (Windows cp1252 regression)
# =============================================================================


def test_text_output_is_pure_ascii_even_with_rule_authored_unicode():
    """Rule authors routinely put em-dashes / smart quotes / ellipses into
    titles / descriptions / remediations.  Those Unicode glyphs used to
    flow straight through the text reporter into the saved file, where
    a Windows PowerShell pipe (which re-decodes the UTF-8 bytes as
    cp1252) would surface them as mojibake like ``â€"``.

    The reporter must flatten its final output to 7-bit ASCII.
    """
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="SEC-UNI-001",
            severity=Severity.HIGH,
            title="Timeout \u2014 runs forever",
            description="Smart \u201cquotes\u201d and \u2026 ellipsis",
            file=".github/workflows/a.yml",
            line=1,
            remediation="Use foo \u2013 like this",
            threat_narrative="A \u2022 B \u2192 C",
        )
    )
    report.summarize()
    output = format_text(report, use_color=False)
    # Pure ASCII: no byte above 0x7F.
    output.encode("ascii")
    # Specifically: every Unicode glyph we seeded has been replaced.
    for bad in ("\u2014", "\u2013", "\u201c", "\u201d", "\u2026", "\u2022", "\u2192"):
        assert bad not in output, f"Raw {bad!r} leaked into text output"
    # And the meaning is preserved — dash -> '-', arrow -> '->', ellipsis -> '...'.
    assert "Timeout - runs forever" in output
    assert '"quotes"' in output
    assert "... ellipsis" in output
    assert "A * B -> C" in output


def test_score_output_is_pure_ascii():
    """The --score block uses `sep_char()` / `em_dash_char()` which return
    Unicode glyphs on UTF-8-capable TTYs.  The reporter's final output
    must still be 7-bit ASCII so a redirected pipe lands cleanly in any
    cp1252 consumer (Windows PowerShell Out-File, legacy log tools).
    """
    from taintly.reporters.score_text import format_score
    from taintly.scorer import compute_score

    report = AuditReport(repo_path="/repo", platform="github")
    report.add(
        Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.HIGH,
            title="Unpinned action",
            description="x",
            file=".github/workflows/a.yml",
            line=1,
        )
    )
    report.summarize()
    score = compute_score(report.findings, files_scanned=1)
    output = format_score(score, use_color=False)
    output.encode("ascii")  # raises if any non-ASCII byte is present


def test_to_ascii_maps_common_typography():
    """The typography table covers the glyphs rule authors actually use.

    Exercising these is cheap insurance: if a rule author adds a new
    glyph we don't map, `to_ascii` falls back to '?' — which at least
    guarantees no mojibake, just a visible question mark.
    """
    from taintly.reporters._encoding import to_ascii

    assert to_ascii("a\u2014b") == "a-b"  # em-dash
    assert to_ascii("a\u2013b") == "a-b"  # en-dash
    assert to_ascii("a\u2212b") == "a-b"  # minus sign
    assert to_ascii("\u201chi\u201d") == '"hi"'
    assert to_ascii("\u2018hi\u2019") == "'hi'"
    assert to_ascii("x\u2026") == "x..."
    assert to_ascii("a\u2192b") == "a->b"
    assert to_ascii("a\u2190b") == "a<-b"
    assert to_ascii("\u2713 ok") == "OK ok"
    assert to_ascii("\u2717 no") == "X no"
    assert to_ascii("a\u00a0b") == "a b"  # NBSP -> space
    assert to_ascii("\u2022 bullet") == "* bullet"
    assert to_ascii("\u25b8 tri") == "> tri"
    # Unknown non-ASCII code point -> '?' (safe fallback, never mojibake).
    assert to_ascii("hello \U0001f600 world") == "hello ? world"
    # Pure ASCII input is untouched.
    assert to_ascii("plain ascii 123!") == "plain ascii 123!"
    # Empty / None-ish handling.
    assert to_ascii("") == ""


def test_encoding_fallbacks_when_cp1252(monkeypatch):
    """Verify box-drawing / arrow / check chars have ASCII fallbacks.

    On Windows terminals with cp1252 encoding, '═', '→', '✓', '✗' cannot be
    encoded and would either crash or display as gibberish. The helpers must
    return ASCII substitutes in that case.
    """
    import io

    import taintly.reporters._encoding as enc

    fake = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr("sys.stdout", fake)

    assert enc.sep_char() == "="
    assert enc.arrow_char() == "->"
    assert enc.check_char() == "OK"
    assert enc.cross_char() == "X"


def test_ensure_utf8_stdout_is_idempotent_and_safe(monkeypatch):
    """ensure_utf8_stdout must not raise when reconfigure is missing."""
    import taintly.reporters._encoding as enc

    class _NoReconfigure:
        encoding = "cp1252"

        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdout", _NoReconfigure())
    monkeypatch.setattr("sys.stderr", _NoReconfigure())
    enc.ensure_utf8_stdout()  # must not raise
    enc.ensure_utf8_stdout()  # idempotent
    enc.force_ascii(False)  # reset shared state


def test_force_ascii_via_env_var(monkeypatch):
    """CICD_AUDIT_ASCII=1 must force pure-ASCII output even on a UTF-8 TTY."""
    import io

    import taintly.reporters._encoding as enc

    monkeypatch.setenv("CICD_AUDIT_ASCII", "1")
    # A genuinely UTF-8-capable stream that would normally pass encode checks.
    utf8 = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    monkeypatch.setattr("sys.stdout", utf8)
    monkeypatch.setattr("sys.stderr", utf8)

    enc.ensure_utf8_stdout()
    try:
        assert enc.sep_char() == "="
        assert enc.arrow_char() == "->"
        assert enc.check_char() == "OK"
        assert enc.em_dash_char() == "-"
    finally:
        enc.force_ascii(False)


def test_windows_redirected_stdout_forces_ascii(monkeypatch):
    """On Windows, a non-TTY stdout (pipe / Out-File) must force ASCII.

    Rationale: PowerShell re-decodes pipe bytes through [Console]::OutputEncoding,
    so any UTF-8 we write becomes cp1252 mojibake in the consumer's file. We
    can't control the consumer, so we stay ASCII in that scenario.
    """
    import io

    import taintly.reporters._encoding as enc

    class _NonTTY(io.TextIOWrapper):
        def isatty(self):
            return False

    fake_stdout = _NonTTY(io.BytesIO(), encoding="utf-8", errors="replace")
    monkeypatch.setattr("os.name", "nt")
    monkeypatch.setattr("sys.stdout", fake_stdout)
    monkeypatch.setattr("sys.stderr", fake_stdout)
    # Ensure no leaking env override from the previous test.
    monkeypatch.delenv("CICD_AUDIT_ASCII", raising=False)

    enc.ensure_utf8_stdout()
    try:
        # Even though the encoding is utf-8, we force ASCII on redirected
        # Windows stdout because the consumer likely re-decodes.
        assert enc.sep_char() == "="
        assert enc.arrow_char() == "->"
        assert enc.check_char() == "OK"
        assert enc.cross_char() == "X"
        assert enc.em_dash_char() == "-"
        assert enc.bullet_char() == "*"
    finally:
        enc.force_ascii(False)


def test_cli_auto_disables_ansi_colors_when_stdout_not_tty(tmp_path):
    """Regression: ``taintly > report.txt`` was writing raw ``\\x1b[91m``
    escape sequences into the saved file because ``use_color`` defaulted to
    True regardless of whether stdout was a terminal.

    Running the CLI with ``capture_output=True`` (subprocess pipes stdout)
    makes ``sys.stdout.isatty()`` return False, which must auto-disable
    colour in the text reporter and the score reporter.
    """
    import subprocess
    import sys

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
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
    # No --no-color flag: the CLI should infer it from the non-TTY stdout.
    # Strip FORCE_COLOR from the child env so the test is insulated from a
    # developer who sets it locally.
    import os as _os

    env = {k: v for k, v in _os.environ.items() if k != "FORCE_COLOR"}
    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path), "--score"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert "\x1b[" not in result.stdout, (
        "Text output piped to a file must not contain ANSI escape codes. "
        "The CLI should detect non-TTY stdout and disable colour."
    )


def test_cli_force_color_env_keeps_ansi_on_non_tty(tmp_path):
    """FORCE_COLOR=1 must override the non-TTY auto-disable, matching the
    convention used by ripgrep / eslint / pytest / npm."""
    import os as _os
    import subprocess
    import sys

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
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
    env = dict(_os.environ)
    env["FORCE_COLOR"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    # The finding triggers HIGH severity output which is colourised.
    assert "\x1b[" in result.stdout, (
        "FORCE_COLOR=1 should preserve ANSI escape codes even when stdout is piped."
    )


def test_posix_redirected_stdout_keeps_unicode(monkeypatch):
    """On POSIX, a non-TTY stdout is fine — no re-decoding layer in between."""
    import io

    import taintly.reporters._encoding as enc

    class _NonTTY(io.TextIOWrapper):
        def isatty(self):
            return False

    fake_stdout = _NonTTY(io.BytesIO(), encoding="utf-8", errors="replace")
    monkeypatch.setattr("os.name", "posix")
    monkeypatch.setattr("sys.stdout", fake_stdout)
    monkeypatch.setattr("sys.stderr", fake_stdout)
    monkeypatch.delenv("CICD_AUDIT_ASCII", raising=False)

    enc.ensure_utf8_stdout()
    try:
        # UTF-8 encoding + POSIX redirection → keep the glyphs.
        assert enc.sep_char() == "═"
        assert enc.arrow_char() == "→"
    finally:
        enc.force_ascii(False)
