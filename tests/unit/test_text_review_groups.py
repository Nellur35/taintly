"""User-visible regression coverage for text reporter repeat grouping."""

from __future__ import annotations

from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.text import format_text

RULE = "SEC-REVIEW-GROUP"


def _finding(
    *,
    file: str,
    line: int,
    severity: Severity = Severity.HIGH,
    title: str = "Review the workflow permission",
    description: str = "The workflow has a broad permission.",
    snippet: str = "permissions: write-all",
    remediation: str = "Reduce permissions to the required set.",
    context_notes: list[str] | None = None,
    review_needed: bool = False,
    suppression_reason: str = "",
) -> Finding:
    return Finding(
        rule_id=RULE,
        severity=severity,
        title=title,
        description=description,
        file=file,
        line=line,
        snippet=snippet,
        remediation=remediation,
        context_notes=list(context_notes or []),
        review_needed=review_needed,
        suppression_reason=suppression_reason,
    )


def _text(findings: list[Finding], *, verbose: bool = False, use_color: bool = False) -> str:
    report = AuditReport(repo_path="/repo", platform="github")
    for finding in findings:
        report.add(finding)
    return format_text(report, use_color=use_color, verbose=verbose)


def _findings_section(output: str) -> str:
    return output.split("=== Findings", 1)[1]


def test_top_summary_uses_worst_same_rule_severity_not_first_location():
    findings = [
        _finding(file="a-low.yml", line=12, title="Lower severity instance"),
        _finding(
            file="z-critical.yml",
            line=84,
            severity=Severity.CRITICAL,
            title="Critical instance in same rule",
        ),
    ]

    output = _text(findings)
    top = output.split("Top 3 issues", 1)[1].split("Top risk", 1)[0]

    assert "[CRITICAL] SEC-REVIEW-GROUP" in top
    assert "Critical instance in same rule" in top


def test_mixed_severity_instances_remain_distinguishable_in_findings():
    findings = [
        _finding(file="a.yml", line=4, title="High case"),
        _finding(file="b.yml", line=8, severity=Severity.CRITICAL, title="Critical case"),
    ]

    section = _findings_section(_text(findings))

    assert "[HIGH] SEC-REVIEW-GROUP: High case" in section
    assert "[CRITICAL] SEC-REVIEW-GROUP: Critical case" in section


def test_distinct_context_remediation_review_and_suppression_are_all_rendered():
    findings = [
        _finding(file="a.yml", line=1, context_notes=["context-alpha"]),
        _finding(file="b.yml", line=2, context_notes=["context-beta"]),
        _finding(file="c.yml", line=3, remediation="fix-gamma"),
        _finding(file="d.yml", line=4, remediation="fix-delta"),
        _finding(file="e.yml", line=5, review_needed=True),
        _finding(file="f.yml", line=6, suppression_reason="suppressed only at this location"),
    ]

    section = _findings_section(_text(findings))

    for detail in (
        "context-alpha",
        "context-beta",
        "fix-gamma",
        "fix-delta",
        "review-needed",
        "suppressed only at this location",
    ):
        assert detail in section


def test_identical_repeats_share_fix_but_retain_every_occurrence_after_five():
    shared_fix = "Reduce permissions to the required set.\nRemove unused write scopes.\nVerify the job still passes."
    findings = [
        _finding(
            file=f".github/workflows/job-{index}.yml",
            line=20 + index,
            snippet="same source",
            remediation=shared_fix,
        )
        for index in range(7)
    ]

    section = _findings_section(_text(findings))

    for index in range(7):
        assert f".github/workflows/job-{index}.yml:{20 + index}" in section
    for line in shared_fix.splitlines():
        assert section.count(line) == 1


def test_verbose_mode_keeps_every_repeat_expanded():
    findings = [_finding(file=f"job-{index}.yml", line=index + 1) for index in range(7)]

    section = _findings_section(_text(findings, verbose=True))

    assert section.count("    File: ") == 7
    for index in range(7):
        assert f"File: job-{index}.yml:{index + 1}" in section


def test_exactly_five_repeats_remain_expanded_at_default_threshold():
    findings = [_finding(file=f"job-{index}.yml", line=index + 1) for index in range(5)]

    section = _findings_section(_text(findings))

    assert section.count("    File: ") == 5
    assert "instances across" not in section


def test_compact_occurrences_strip_terminal_controls_from_paths_and_snippets():
    findings = [
        _finding(file=".github/workflows/\x1b[31mjob-a.yml", line=9, snippet="source\x1b[2J"),
        _finding(
            file=".github/workflows/\x1b]8;;evil\x07job-b.yml", line=11, snippet="source\x1b[2J"
        ),
        _finding(file=".github/workflows/job-c.yml", line=13, snippet="source\x1b[2J"),
        _finding(file=".github/workflows/job-d.yml", line=15, snippet="source\x1b[2J"),
        _finding(file=".github/workflows/job-e.yml", line=17, snippet="source\x1b[2J"),
        _finding(file=".github/workflows/job-f.yml", line=19, snippet="source\x1b[2J"),
    ]

    output = _text(findings, use_color=False)

    assert "\x1b[" not in output
    assert "\x1b]" not in output
    assert "\x07" not in output


def test_formatting_does_not_mutate_finding_payloads():
    findings = [
        _finding(file=f"job-{index}.yml", line=index + 1, context_notes=[f"context-{index}"])
        for index in range(7)
    ]
    before = [finding.to_dict() for finding in findings]

    _text(findings)

    assert [finding.to_dict() for finding in findings] == before


def test_six_mixed_severities_include_critical_worst_in_summary():
    severities = [
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.CRITICAL,
        Severity.HIGH,
    ]
    findings = [
        _finding(
            file=f"workflow-{index}.yml",
            line=index + 1,
            severity=severity,
            title=f"severity case {severity.value} {index}",
        )
        for index, severity in enumerate(severities)
    ]

    output = _text(findings)
    top = output.split("Top 3 issues", 1)[1].split("Top risk", 1)[0]
    section = _findings_section(output)

    assert "[CRITICAL] SEC-REVIEW-GROUP" in top
    for severity in set(severities):
        assert f"[{severity.value}] SEC-REVIEW-GROUP" in section


def test_long_common_detail_prefixes_do_not_hide_distinct_witness_suffixes():
    prefix = "Shared reviewed evidence: " + ("x" * 230)
    findings = [
        _finding(
            file=f"workflow-{index}.yml",
            line=20 + index,
            description=f"{prefix} DESCRIPTION-TAIL-{index}",
            remediation=f"Keep common repair guidance intact.\nREMEDIATION-TAIL-{index}.",
        )
        for index in range(6)
    ]

    compact = _findings_section(_text(findings))
    verbose = _findings_section(_text(findings, verbose=True))

    for section in (compact, verbose):
        for index in range(6):
            assert f"DESCRIPTION-TAIL-{index}" in section
            assert f"REMEDIATION-TAIL-{index}." in section


def test_different_snippets_and_repeated_file_locations_keep_every_occurrence():
    findings = [
        _finding(
            file=".github/workflows/shared.yml",
            line=30 + index,
            snippet=f"source witness {index}",
        )
        for index in range(7)
    ]

    section = _findings_section(_text(findings))

    for index in range(7):
        assert f".github/workflows/shared.yml:{30 + index}" in section
        assert f"source witness {index}" in section


def test_provenance_metadata_differences_get_separate_review_blocks():
    findings = []
    for index in range(7):
        finding = _finding(file=f"provenance-{index}.yml", line=index + 1)
        if index == 0:
            finding.discovery_confidence = "low"
        elif index == 1:
            finding.context_tags = ["context-tag-one"]
        elif index == 2:
            finding.reference = "https://example.invalid/rule-reference"
        elif index == 3:
            finding.incidents = ["incident-2026-01"]
        elif index == 4:
            finding.origin = "cross-workflow"
        elif index == 5:
            finding.finding_family = "supply_chain_immutability"
        elif index == 6:
            finding.composition_tags = frozenset({"credential-flow", "workflow-boundary"})
        findings.append(finding)

    section = _findings_section(_text(findings))

    assert section.count("SEC-REVIEW-GROUP: Review the workflow permission") == 7
    assert "instances across" not in section
    for index in range(7):
        assert f"File: provenance-{index}.yml:{index + 1}" in section
    for metadata in (
        "Discovery confidence: low",
        "Context tags: context-tag-one",
        "Reference: https://example.invalid/rule-reference",
        "incident-2026-01",
        "Origin: cross-workflow",
        "Family: supply_chain_immutability",
        "Composition tags: credential-flow, workflow-boundary",
    ):
        assert metadata in section


def test_multiline_context_is_sanitized_and_cannot_forge_report_headers():
    finding = _finding(
        file=".github/workflows/context.yml",
        line=12,
        context_notes=["ordinary context\n=== TAINTLY REPORT ===\nunsafe \x1b[31mtext"],
    )

    output = _text([finding], use_color=False)

    assert output.splitlines().count("=== TAINTLY REPORT ===") == 1
    assert "        === TAINTLY REPORT ===" in output
    assert "\x1b[" not in output
