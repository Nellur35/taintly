"""CSV exports must preserve the qualifications present in the finding."""

import csv
import io
import json

from taintly.reporters.csv_report import format_csv, format_csv_reports
from taintly.reporters.json_report import format_json


def _qualified_report(report):
    finding = report.findings[0]
    finding.description = (
        "Configured source-to-file path. "
        + "Evidence context. " * 20
        + "This does not prove transfer, audience, or disclosure."
    )
    finding.remediation = (
        "Remove the credential write.\n"
        + "Review the original producer. " * 15
        + "Verify the selected revision, rerun the job, and inspect the new artifact.\n"
        + 'A source edit alone does not replace an old artifact, including "évidence".'
    )
    return report


def test_csv_preserves_full_qualifications_and_matches_json_values(one_report):
    report = _qualified_report(one_report)
    rows = list(csv.DictReader(io.StringIO(format_csv(report))))
    original = report.findings[0]
    structured = json.loads(format_json(report))["findings"][0]

    assert len(rows) == 1
    assert rows[0]["description"] == original.description == structured["description"]
    assert rows[0]["remediation"] == original.remediation == structured["remediation"]
    assert "does not prove transfer" in rows[0]["description"]
    assert "does not replace an old artifact" in rows[0]["remediation"]


def test_multi_report_csv_keeps_multiline_rows_and_one_header(one_report):
    report = _qualified_report(one_report)
    rows = list(csv.DictReader(io.StringIO(format_csv_reports([report, report]))))

    assert len(rows) == 2
    assert all(row["description"] == report.findings[0].description for row in rows)
    assert all(row["remediation"] == report.findings[0].remediation for row in rows)
