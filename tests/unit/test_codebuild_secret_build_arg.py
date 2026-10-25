"""Authored source/consumer and uncertainty contrasts for CodeBuild build args."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.models import Platform
from taintly.reporters.json_report import format_json
from taintly.rules.registry import load_rules_for_platform


def _source(command: str, *, preceding: str = "", shell: str = "") -> str:
    return (
        "version: 0.2\n"
        "env:\n"
        + (f"  shell: {shell}\n" if shell else "")
        + "  secrets-manager:\n    TOKEN: prod/token\n    SECOND: prod/second\n"
        "phases:\n  build:\n    commands:\n" + preceding + "      - " + command + "\n"
    )


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "buildspec.yml"
    path.write_text(source, encoding="utf8")
    return scan_file(str(path), load_rules_for_platform(Platform.CODEBUILD))


def _selected(findings):
    return [finding for finding in findings if finding.rule_id == "SEC6-CB-004"]


def _incomplete(findings):
    return any(
        finding.rule_id == "ENGINE-ERR" and "SEC6-CB-004" in finding.description
        for finding in findings
    )


def test_two_source_bound_args_survive_engine_and_json(tmp_path: Path) -> None:
    source = _source(
        "docker build --build-arg A=$TOKEN --build-arg B=${TOKEN} "
        "--build-arg C=$SECOND --build-arg PUBLIC=ready -t app ."
    )
    findings = _scan(tmp_path, source)
    selected = _selected(findings)
    assert len(selected) == 1
    assert selected[0].review_needed
    notes = " ".join(selected[0].context_notes)
    assert hashlib.sha256((tmp_path / "buildspec.yml").read_bytes()).hexdigest() in notes
    assert "Docker --build-arg A" in notes
    assert "Docker --build-arg B" in notes
    assert "Docker --build-arg C" in notes
    assert "PUBLIC" not in notes
    assert "image metadata" in notes

    report = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.CODEBUILD), platform=Platform.CODEBUILD
    )[0]
    output = json.loads(format_json(report))
    assert len([item for item in output["findings"] if item["rule_id"] == "SEC6-CB-004"]) == 1


def test_bare_arg_inherits_bound_environment_variable(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _source("docker build --build-arg TOKEN -t app ."))
    assert len(_selected(findings)) == 1


@pytest.mark.parametrize(
    "command",
    [
        "docker build --build-arg TOKEN=public -t app .",
        "docker build --build-arg 'TOKEN=$TOKEN' -t app .",
        "echo docker build --build-arg TOKEN=$TOKEN -t app .",
        "docker login -u user --password-stdin && docker build -t app .",
    ],
)
def test_public_literal_and_nonexecuting_text_do_not_claim_transfer(
    tmp_path: Path, command: str
) -> None:
    findings = _scan(tmp_path, _source(command))
    assert not _selected(findings)
    if command.startswith("echo "):
        assert not _incomplete(findings)


def test_complex_form_keeps_valid_witness_and_marks_unknown(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        _source("docker build --build-arg A=$TOKEN --build-arg B=prefix$SECOND -t app ."),
    )
    assert len(_selected(findings)) == 1
    assert _incomplete(findings)


@pytest.mark.parametrize(
    ("source", "expected_incomplete"),
    [
        (
            _source(
                "docker build --build-arg TOKEN=$TOKEN -t app .", preceding="      - TOKEN=public\n"
            ),
            True,
        ),
        (_source("docker build --build-arg TOKEN=$TOKEN -t app .", shell="powershell.exe"), True),
        (_source('docker build --build-arg TOKEN="$TOKEN" -t app .'), True),
    ],
)
def test_overrides_or_unsupported_shell_forms_remain_unresolved(
    tmp_path: Path, source: str, expected_incomplete: bool
) -> None:
    findings = _scan(tmp_path, source)
    assert not _selected(findings)
    assert _incomplete(findings) is expected_incomplete


def test_override_of_one_source_keeps_other_witness(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        _source(
            "docker build --build-arg A=$TOKEN --build-arg B=$SECOND -t app .",
            preceding="      - TOKEN=public\n",
        ),
    )
    selected = _selected(findings)
    assert len(selected) == 1
    notes = " ".join(selected[0].context_notes)
    assert "Docker --build-arg B" in notes
    assert "Docker --build-arg A" not in notes
    assert _incomplete(findings)
