"""Coverage failures are diagnostics, not security risk conclusions."""

import json

import pytest

from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.html_report import format_html
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif
from taintly.reporters.text import format_text


def report_with(*ids):
    report = AuditReport(repo_path="/example", platform="github")
    report.files_scanned = 1
    for rule_id in ids:
        report.add(
            Finding(
                rule_id=rule_id,
                severity=Severity.INFO,
                title="Coverage exhausted" if rule_id == "ENGINE-ERR" else rule_id,
                description="description",
                file="ci.yml",
                review_needed=rule_id in {"SEC6-GH-015", "SEC3-GH-006"},
            )
        )
    report.summarize()
    return report


def test_error_only_json_has_zero_security_risks_and_keeps_raw_diagnostics():
    data = json.loads(format_json(report_with("ENGINE-ERR")))
    assert data["distinct_risk_count"] == 0
    assert data["review_needed_count"] == 0
    assert data["families"] == []
    assert data["security_findings_count"] == 0
    assert data["engine_error_count"] == 1
    assert data["coverage_status"] == "incomplete"
    assert data["findings_count"] == 1  # existing compatibility count
    assert len(data["errors"]) == len(data["findings"]) == 1


def test_error_only_text_does_not_claim_clean_completion():
    output = format_text(report_with("ENGINE-ERR"), use_color=False)
    assert "Coverage degraded" in output
    assert "No findings." not in output
    assert "scan incomplete" in output.lower()


def test_error_only_html_discloses_coverage_without_security_risk():
    output = format_html(report_with("ENGINE-ERR"))
    assert "Scan incomplete" in output
    assert 'id="coverage-h"' in output
    assert '<div class="num">0</div><div class="lbl">distinct risks' in output
    assert 'id="risks-h"' not in output


def test_mixed_json_separates_security_inventory_and_error_counts():
    data = json.loads(format_json(report_with("SEC6-GH-015", "SEC3-GH-006", "ENGINE-ERR")))
    assert data["security_findings_count"] == 1
    assert data["inventory_count"] == 1
    assert data["engine_error_count"] == 1
    assert data["distinct_risk_count"] == 0
    assert data["review_needed_count"] == 1
    assert len(data["findings"]) == data["findings_count"] + data["inventory_count"] == 3


def test_mixed_text_never_labels_review_inventory_or_error_as_to_fix():
    output = format_text(report_with("SEC6-GH-015", "SEC3-GH-006", "ENGINE-ERR"), use_color=False)
    assert "to fix" not in output
    summary = output.split("Summary", 1)[1].split("Findings (", 1)[0]
    assert "0 confirmed, 1 review-needed" in summary
    assert "[INFO] ENGINE-ERR" not in summary
    assert "[INFO] SEC3-GH-006" not in summary


def test_sarif_counts_match_json_but_preserve_error_notification_channel():
    report = report_with("SEC6-GH-015", "SEC3-GH-006", "ENGINE-ERR")
    data = json.loads(format_json(report))
    run = json.loads(format_sarif(report))["runs"][0]
    for key in (
        "findings_count",
        "inventory_count",
        "security_findings_count",
        "engine_error_count",
        "coverage_status",
    ):
        assert run["properties"][key] == data[key]
    assert len(run["invocations"][0]["toolExecutionNotifications"]) == 1
    assert {r["ruleId"] for r in run["results"]} == {"SEC6-GH-015", "SEC3-GH-006", "ENGINE-ERR"}


def test_empty_report_does_not_claim_semantic_completeness():
    report = report_with()
    data = json.loads(format_json(report))
    assert data["coverage_status"] == "not_established"
    assert data["engine_error_count"] == data["security_findings_count"] == 0
    assert "No findings." in format_text(report, use_color=False)
    assert "semantic completeness is not proven" in format_text(report, use_color=False)
    assert "Scan incomplete" not in format_html(report)


def test_coverage_titles_remain_escaped_in_html():
    report = report_with("ENGINE-ERR")
    report.findings[0].title = '<img src=x onerror="attack()">'
    output = format_html(report)
    assert "<img src=x" not in output
    assert "&lt;img" in output


def test_multiple_errors_in_one_file_do_not_claim_multiple_files():
    output = format_text(report_with("ENGINE-ERR", "ENGINE-ERR"), use_color=False)
    assert "Coverage degraded on 1 file(s)" in output


@pytest.mark.parametrize(
    ("ids", "security", "inventory", "errors", "confirmed", "review"),
    [
        ((), 0, 0, 0, 0, 0),
        (("SEC3-GH-006",), 0, 1, 0, 0, 0),
        (("SEC3-GH-001",), 1, 0, 0, 1, 0),
        (("SEC6-GH-015",), 1, 0, 0, 0, 1),
        (("ENGINE-ERR", "SEC3-GH-006"), 0, 1, 1, 0, 0),
        (("ENGINE-ERR", "SEC3-GH-001"), 1, 0, 1, 1, 0),
    ],
)
def test_complete_and_mixed_partitions(ids, security, inventory, errors, confirmed, review):
    report = report_with(*ids)
    data = json.loads(format_json(report))
    assert data["security_findings_count"] == security
    assert data["inventory_count"] == inventory
    assert data["engine_error_count"] == errors
    assert data["distinct_risk_count"] == confirmed
    assert data["review_needed_count"] == review
    assert data["coverage_status"] == ("incomplete" if errors else "not_established")
    assert len(data["findings"]) == security + inventory + errors
    html = format_html(report)
    assert ("Scan incomplete" in html) == bool(errors)
    assert ('id="risks-h"' in html) == bool(confirmed)
