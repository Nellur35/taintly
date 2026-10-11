"""Coverage-status contracts for bounded file-scope searches."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from taintly.engine import scan_file
from taintly.models import (
    _CHUNK_COVERAGE_CEILING,
    _MAX_SAFE_TEXT_LEN,
    AbsencePattern,
    AuditReport,
    ContextPattern,
    Platform,
    Rule,
    Severity,
)
from taintly.reporters.json_report import format_json
from taintly.reporters.text import format_text


def _rule(rule_id: str, pattern) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description="Synthetic coverage contract",
        pattern=pattern,
        remediation="Test only",
        reference="https://example.com",
    )


def _large_benign_workflow() -> str:
    filler = "  # generated but benign padding for chunked scan\n"
    count = (2 * _MAX_SAFE_TEXT_LEN) // len(filler)
    return (
        "on: pull_request\n"
        "jobs:\n"
        "  verify:\n"
        "    steps:\n" + filler * count + "      - name: required marker\n"
        "        run: echo required_marker\n"
        "      - name: tail signal\n"
        "        run: echo deploy_to_production\n"
    )


def test_chunked_band_scans_absence_and_context_patterns_through_tail(tmp_path: Path):
    content = _large_benign_workflow()
    assert _MAX_SAFE_TEXT_LEN < len(content) < _CHUNK_COVERAGE_CEILING
    path = tmp_path / "chunked.yml"
    path.write_text(content, encoding="utf-8")
    rules = [
        _rule("TEST-ABSENCE", AbsencePattern(absent="required_marker")),
        _rule(
            "TEST-CONTEXT-TAIL",
            ContextPattern(anchor="deploy_to_production", requires="pull_request"),
        ),
    ]

    findings = scan_file(str(path), rules=rules)

    ids = {finding.rule_id for finding in findings}
    assert "TEST-CONTEXT-TAIL" in ids  # positive match is beyond the first chunk
    assert "TEST-ABSENCE" not in ids  # tail marker disproves absence
    assert "ENGINE-ERR" not in ids

    report = AuditReport(repo_path=str(tmp_path), platform="github")
    for finding in findings:
        report.add(finding)
    report.summarize()
    payload = json.loads(format_json(report))
    assert payload["errors"] == []
    text = format_text(report, use_color=False)
    assert "Coverage degraded" not in text


def test_chunked_band_cli_json_exits_clean_without_coverage_banner(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    content = _large_benign_workflow()
    assert _MAX_SAFE_TEXT_LEN < len(content) < _CHUNK_COVERAGE_CEILING
    (workflows / "chunk.yml").write_text(content, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(tmp_path), "--no-config", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["errors"] == []
    assert "Coverage degraded" not in result.stdout


def test_genuine_chunk_ceiling_loss_remains_an_engine_error(tmp_path: Path):
    path = tmp_path / "over-ceiling.yml"
    line = "# bounded coverage control\n"
    path.write_text(line * (_CHUNK_COVERAGE_CEILING // len(line) + 2), encoding="utf-8")

    findings = scan_file(str(path), rules=[])
    errors = [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    assert any("chunked-coverage ceiling" in finding.title for finding in errors)

    report = AuditReport(repo_path=str(tmp_path), platform="github")
    for finding in findings:
        report.add(finding)
    report.summarize()
    assert json.loads(format_json(report))["errors"]
    assert "Coverage degraded" in format_text(report, use_color=False)


def test_short_line_chunk_exhaustion_remains_an_engine_error(tmp_path: Path, monkeypatch):
    import taintly.models as models

    monkeypatch.setattr(models, "_MAX_SAFE_TEXT_LEN", 4)
    monkeypatch.setattr(models, "_CHUNK_LINES", 2)
    monkeypatch.setattr(models, "_CHUNK_OVERLAP_LINES", 0)
    monkeypatch.setattr(models, "_MAX_CHUNKS", 2)
    path = tmp_path / "many-lines.yml"
    path.write_text("x\n" * 6 + "required_marker\n", encoding="utf-8")
    findings = scan_file(
        str(path), rules=[_rule("TEST-ABSENCE", AbsencePattern(absent="required_marker"))]
    )

    assert not any(finding.rule_id == "TEST-ABSENCE" for finding in findings)
    assert any(
        finding.rule_id == "ENGINE-ERR" and "ended before full coverage" in finding.title
        for finding in findings
    )


def test_time_boxed_or_missing_file_still_reports_engine_error(tmp_path: Path):
    path = tmp_path / "small.yml"
    path.write_text("on: push\n", encoding="utf-8")
    time_boxed = scan_file(
        str(path), rules=[_rule("TEST-ABSENCE", AbsencePattern(absent="never"))], max_scan_seconds=0
    )
    missing = scan_file(str(tmp_path / "missing.yml"), rules=[])

    assert any("time-boxed" in f.title for f in time_boxed if f.rule_id == "ENGINE-ERR")
    assert any(f.rule_id == "ENGINE-ERR" for f in missing)
