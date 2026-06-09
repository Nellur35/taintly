"""Determinism + GHAS-fingerprint guarantees for the machine-readable reporters.

A1 — SARIF/JSON output is stable regardless of the order findings were collected,
so GitHub Advanced Security / GitLab dashboards don't churn on incidental
reordering (and the output is byte-identical across runs on identical input).

A2 — every SARIF result carries a stable ``partialFingerprints`` entry so GHAS can
dedup a finding across runs even when it drifts to a different line (the fingerprint
deliberately excludes the line number; see ``baseline.fingerprint``).
"""

from __future__ import annotations

import json

from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif


def _finding(rule_id: str, file: str, line: int, snippet: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file=file,
        line=line,
        snippet=snippet,
    )


def _report(findings: list[Finding]) -> AuditReport:
    report = AuditReport(repo_path="/repo", platform="github")
    for f in findings:
        report.add(f)
    report.summarize()
    return report


# Deliberately unsorted, with two findings sharing a rule_id and a file so the
# (file, line, rule_id) tie-break is exercised.
_FINDINGS = [
    _finding("SEC3-GH-001", ".github/workflows/b.yml", 20, "b1"),
    _finding("SEC4-GH-004", ".github/workflows/a.yml", 5, "a1"),
    _finding("SEC3-GH-001", ".github/workflows/a.yml", 5, "a0"),
    _finding("AI-GH-001", ".github/workflows/a.yml", 99, "a9"),
]


def test_sarif_byte_identical_regardless_of_collection_order():
    forward = format_sarif(_report(_FINDINGS))
    backward = format_sarif(_report(list(reversed(_FINDINGS))))
    assert forward == backward


def test_json_findings_order_independent_and_sorted():
    forward = json.loads(format_json(_report(_FINDINGS)))["findings"]
    backward = json.loads(format_json(_report(list(reversed(_FINDINGS)))))["findings"]
    assert forward == backward
    keys = [(f["file"], f["line"], f["rule_id"]) for f in forward]
    assert keys == sorted(keys)


def test_sarif_results_sorted_by_file_line_rule():
    sarif = json.loads(format_sarif(_report(list(reversed(_FINDINGS)))))
    keys = [
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["ruleId"],
        )
        for r in sarif["runs"][0]["results"]
    ]
    assert keys == sorted(keys)


def test_every_sarif_result_carries_a_partial_fingerprint():
    sarif = json.loads(format_sarif(_report(_FINDINGS)))
    for r in sarif["runs"][0]["results"]:
        fp = r.get("partialFingerprints", {}).get("taintlyFingerprintV1")
        assert fp and len(fp) == 64, f"missing/short fingerprint on {r.get('ruleId')}"


def test_partial_fingerprint_excludes_line_number():
    """A finding that drifts to a different line keeps the same fingerprint —
    the property GHAS relies on to dedup across runs."""
    same = "      - uses: actions/checkout@v4"
    at_12 = json.loads(format_sarif(_report([_finding("SEC3-GH-001", "a.yml", 12, same)])))
    at_900 = json.loads(format_sarif(_report([_finding("SEC3-GH-001", "a.yml", 900, same)])))
    fp_12 = at_12["runs"][0]["results"][0]["partialFingerprints"]["taintlyFingerprintV1"]
    fp_900 = at_900["runs"][0]["results"][0]["partialFingerprints"]["taintlyFingerprintV1"]
    assert fp_12 == fp_900
