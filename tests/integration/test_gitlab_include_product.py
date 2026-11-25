"""Public GitLab include discovery and shell ownership through the CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys


def _scan(root):
    shell_env = dict(os.environ, PYTHONUTF8="1")
    for name in ("CI_PIPELINE_SOURCE", "CI_COMMIT_BRANCH", "CI_DEFAULT_BRANCH"):
        shell_env.pop(name, None)
    result = subprocess.run(
        [sys.executable, "-m", "taintly", str(root), "--no-config", "--format", "json"],
        env=shell_env,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.stdout, result.stderr
    return result.returncode, json.loads(result.stdout)


def test_transitive_local_include_retains_the_missing_source_and_the_scan(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    entry.write_text(
        "include: /templates/outer.yml\nentry:\n  script: echo entry\n", encoding="utf-8"
    )
    directory = tmp_path / "templates"
    directory.mkdir()
    outer = directory / "outer.yml"
    outer.write_text(
        "include: {local: /templates/inner.yml}\nverify:\n  script: echo verify\n", encoding="utf-8"
    )

    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 2
    assert report["coverage_status"] == "incomplete"
    assert len(report["errors"]) == 1
    diagnostic = report["errors"][0]
    assert diagnostic["title"] == "Source acquisition incomplete"
    assert diagnostic["file"] == str(outer)
    assert "'/templates/inner.yml'" in diagnostic["description"]

    (directory / "inner.yml").write_text("smoke:\n  script: echo smoke\n", encoding="utf-8")
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 3
    assert not report["errors"]


def test_dynamic_include_has_a_coverage_diagnostic_and_preserves_real_shell_use(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    source = (
        "include:\n"
        "  - local: 'templates/$CI_COMMIT_BRANCH.yml'\n"
        "  - local: templates/$CI_COMMIT_REF_NAME.yml\n"
        "verify:\n"
        "  script: echo ready\n"
    )
    entry.write_text(source, encoding="utf-8")

    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 1
    assert report["coverage_status"] == "incomplete"
    assert len(report["errors"]) == 1
    assert "2 GitLab include(s) interpolate" in report["errors"][0]["title"]
    shell_rules = {"SEC4-GL-001", "SEC4-GL-003"}
    assert not any(row["rule_id"] in shell_rules for row in report["findings"])
    coverage_errors = report["errors"]

    entry.write_text(
        source.replace("echo ready", "echo $CI_COMMIT_BRANCH $CI_COMMIT_REF_NAME"),
        encoding="utf-8",
    )
    code, report = _scan(tmp_path)
    assert code == 1
    assert report["coverage_status"] == "incomplete"
    assert report["errors"] == coverage_errors
    assert {
        (row["rule_id"], row["line"]) for row in report["findings"] if row["rule_id"] in shell_rules
    } == {("SEC4-GL-001", 5), ("SEC4-GL-003", 5)}


def test_wildcard_with_no_matches_can_select_no_includes(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    entry.write_text(
        "include: 'templates/*.yml'\nverify:\n  script: echo verified\n", encoding="utf-8"
    )
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 1
    assert not report["errors"]
