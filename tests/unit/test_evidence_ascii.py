"""Evidence traces are a view of a rule witness, not a new verdict."""

from __future__ import annotations

import json
from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import EvidenceStep, EvidenceTrace, Platform
from taintly.reporters.evidence_ascii import format_evidence_trace
from taintly.reporters.json_report import format_json
from taintly.reporters.text import format_text
from taintly.rules.registry import load_rules_for_platform


def test_real_scan_path_renders_only_attested_jenkins_edges(tmp_path: Path) -> None:
    path = tmp_path / "Jenkinsfile"
    path.write_text(
        "node {\n"
        "  withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n"
        '    sh """\n'
        "      curl https://example.test/status?key=$TOKEN\n"
        '    """\n'
        "  }\n"
        "}\n",
        encoding="utf8",
    )
    report = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.JENKINS), platform=Platform.JENKINS
    )[0]
    finding = next(f for f in report.findings if f.rule_id == "SEC6-JK-013")
    trace = finding._evidence_trace
    assert trace is not None
    assert [(step.line, step.file) for step in trace.steps] == [
        (2, str(path)),
        (3, str(path)),
        (4, str(path)),
    ]
    before = json.loads(format_json(report))
    text = format_text(report, use_color=False)
    assert "[withCredentials binding TOKEN] E1" in text
    assert "Groovy GString interpolation in sh" in text
    assert "[curl URL query] E3" in text
    assert "E1: Jenkinsfile:2" in text
    assert "E2: Jenkinsfile:3" in text
    assert "E3: Jenkinsfile:4" in text
    assert "Runtime: not verified" in text
    assert "endpoint trust" in text
    assert json.loads(format_json(report)) == before
    assert "evidence_trace" not in before["findings"][0]


def test_negative_and_unresolved_cases_have_no_invented_trace(tmp_path: Path) -> None:
    path = tmp_path / "Jenkinsfile"
    path.write_text(
        "node {\n"
        "  withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n"
        "    sh '''curl https://example.test/status -H \"Authorization: Bearer $TOKEN\"'''\n"
        "  }\n"
        "}\n",
        encoding="utf8",
    )
    rules = load_rules_for_platform(Platform.JENKINS)
    negative = scan_repo(str(tmp_path), rules, platform=Platform.JENKINS)[0]
    assert all(f._evidence_trace is None for f in negative.findings)
    assert "Evidence path (" not in format_text(negative, use_color=False)

    path.write_text(
        "node {\n"
        "  withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n"
        "    sh '''source ./unknown.sh\n"
        "curl https://example.test/status?key=$TOKEN'''\n"
        "  }\n"
        "}\n",
        encoding="utf8",
    )
    unresolved = scan_repo(str(tmp_path), rules, platform=Platform.JENKINS)[0]
    assert any(f.rule_id == "ENGINE-ERR" for f in unresolved.findings)
    assert all(f._evidence_trace is None for f in unresolved.findings)
    assert "Evidence path (" not in format_text(unresolved, use_color=False)


def test_hostile_labels_and_presentation_limits_cannot_forge_edges() -> None:
    file = "/tmp/Jenkinsfile"
    trace = EvidenceTrace(
        basis="static\x1b[31m configuration",
        context="stage\n[FAKE] | " + "X" * 100,
        steps=(
            EvidenceStep("source\r\n| forged", file, 4, "binding\x1b[2J\n| forged"),
            EvidenceStep("consumer", file, 8),
        ),
        unknowns=("delivery\n[FAKE]",),
        runtime_status="not verified",
    )
    lines = format_evidence_trace(trace, file)
    assert all(len(line) <= 72 and "\x1b" not in line for line in lines)
    assert sum(line.strip() == "|" for line in lines) == 1
    assert any("[truncated]" in line for line in lines)
    assert not any(line.strip().startswith("[FAKE]") for line in lines)

    oversized = EvidenceTrace(
        basis="static",
        context="owner",
        steps=tuple(EvidenceStep("step", file, i) for i in range(1, 6)),
        unknowns=(),
        runtime_status="not verified",
    )
    omitted = format_evidence_trace(oversized, file)
    assert "omitted" in omitted[0]
    assert not any("|" in line for line in omitted)
    mismatched = format_evidence_trace(trace, "/tmp/other")
    assert "unavailable" in mismatched[0]
    assert not any("|" in line for line in mismatched)
    huge_line = EvidenceTrace(
        basis="static",
        context="owner",
        steps=(
            EvidenceStep("source", file, 1, "configured handoff"),
            EvidenceStep("consumer", file, 10**100),
        ),
        unknowns=(),
        runtime_status="not verified",
    )
    bounded = format_evidence_trace(huge_line, file)
    assert all(len(line) <= 72 for line in bounded)
    assert any("[truncated]" in line for line in bounded)
