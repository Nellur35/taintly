"""Credential previews are a single policy across report and baseline consumers."""

from __future__ import annotations

import json

import pytest

from taintly.baseline import BASELINE_VERSION, apply_diff, fingerprint, load_baseline, save_baseline
from taintly.evidence_redaction import redact_snippet
from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.csv_report import format_csv
from taintly.reporters.html_report import format_html
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif
from taintly.reporters.text import format_text

_VALUE = "SyntheticEvidenceMarker20261122"


def finding(snippet: str, rule: str = "TEST-002", line: int = 7) -> Finding:
    return Finding(
        rule,
        Severity.HIGH,
        "Example finding",
        "Review the evidence.",
        "workflow.yml",
        line=line,
        snippet=snippet,
    )


@pytest.mark.parametrize(
    "preview",
    [
        f'password: "{_VALUE}"',
        f'db_password: "{_VALUE}, with a comma"',
        f'"private_key": {_VALUE} with spaces',
        f"password=#{_VALUE}",
        f"id-token: {_VALUE}",
        f"token: {{not-a-reference {_VALUE}}}",
        f"token: $VARIABLE and {_VALUE}",
        f"--password={_VALUE}",
        f"sh 'docker login -u user -p {_VALUE}'",
        f"https://user:{_VALUE}@registry.example.invalid",
        f"private_key: |-\n  {_VALUE}\n  more key material",
        f'password: "first line\\n  {_VALUE}\\n  last line"',
    ],
)
def test_literal_preview_redaction_preserves_no_part_of_value(preview):
    assert _VALUE not in redact_snippet(preview)
    assert "[REDACTED]" in redact_snippet(preview)


@pytest.mark.parametrize(
    "preview",
    [
        "password: ${{ secrets.DEPLOY_KEY }}",
        'token: "${{ secrets.NAME }}"',
        'PASSWORD="$DEPLOY_KEY"',
        "password: ''",
        "uses: actions/checkout@v4",
        "id-token: write",
        "id-token: none",
        "permissions: {contents: read, id-token: write}",
        "permissions: {id-token: none, contents: read}",
        'id-token: "write"',
    ],
)
def test_symbolic_references_and_other_evidence_remain_visible(preview):
    assert redact_snippet(preview) == preview


def test_reports_redact_the_direct_finding_and_a_second_rule_on_its_line():
    raw = f'password: "{_VALUE}"'
    report = AuditReport("repo", findings=[finding(raw, "SEC6-GH-001"), finding(raw)])
    for render in (format_text, format_json, format_sarif, format_csv, format_html):
        output = render(report)
        assert _VALUE not in output
        if render is not format_html:
            assert "[REDACTED]" in output
    assert report.findings[0].snippet == raw
    rows = json.loads(format_json(report))["findings"]
    assert {(r["rule_id"], r["line"]) for r in rows} == {("SEC6-GH-001", 7), ("TEST-002", 7)}
    assert all("password" in row["snippet"] and _VALUE not in row["match_text"] for row in rows)
    sarif = json.loads(format_sarif(report))
    assert all("partialFingerprints" not in row for row in sarif["runs"][0]["results"])


def test_unknown_preview_from_literal_rule_is_withheld():
    assert finding(_VALUE, "SEC2-GH-003").report_snippet() == "[REDACTED]"


def test_new_and_legacy_baselines_keep_sensitive_findings_visible(tmp_path):
    secret = finding(f"token: {_VALUE}", "TEST-002")
    known = finding("uses: actions/checkout@v4")
    other = finding("run: make build")
    path = tmp_path / "baseline.json"

    save_baseline([secret, known, other], str(tmp_path), str(path))
    data = json.loads(path.read_bytes())
    assert _VALUE not in json.dumps(data)
    assert set(data["snippets"].values()) == {"uses: actions/checkout@v4"}
    assert fingerprint(secret, str(tmp_path)) not in data["fingerprints"]
    assert apply_diff([secret, known, other], load_baseline(str(path)), str(tmp_path)) == (
        [secret],
        2,
    )

    old_hash = fingerprint(secret, str(tmp_path))
    data.update(version=BASELINE_VERSION, snippets={old_hash: secret.snippet})
    data["fingerprints"].append(old_hash)
    path.write_text(json.dumps(data), encoding="utf8")
    legacy = load_baseline(str(path))
    assert legacy.snippets == {}
    assert apply_diff([secret, known, other], legacy, str(tmp_path)) == ([secret], 2)
