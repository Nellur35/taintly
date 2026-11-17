"""Authored controls for the bounded CodeBuild primary selection result."""

import json
import sys

import pytest

from taintly import __main__ as cli
from taintly.ingestion import codebuild_s3
from taintly.ingestion.codebuild_snapshot import SnapshotError

ID = "example:01234567-89ab-cdef-0123-456789abcdef"
ORIGIN = "https://github.com/example/project"
REVISION = "a" * 40
DIRECTORY = (
    "arn:aws:s3:::test-bucket/codebuild/example/01234567-89ab-cdef-0123-456789abcdef/example"
)


@pytest.fixture
def receipt(tmp_path, monkeypatch):
    def require_git(root, identity, revision, label):
        if (root, identity, revision, label) != (tmp_path, "example/project", REVISION, "PR head"):
            raise SnapshotError("Unknown or unrelated source revision")

    monkeypatch.setattr(codebuild_s3, "_require_git_revision", require_git)
    return {
        "schema": "codebuild-managed-s3-empty-primary-v1",
        "build": {
            "id": ID,
            "projectName": "example",
            "buildComplete": True,
            "buildStatus": "FAILED",
            "sourceVersion": "pr/10",
            "resolvedSourceVersion": REVISION,
            "startTime": 10,
            "endTime": 30,
            "secondarySources": [],
            "secondaryArtifacts": [],
            "artifacts": {"type": "S3", "packaging": "NONE"},
            "source": {
                "type": "GITHUB",
                "location": ORIGIN,
                "buildspec": (
                    "version: 0.2\nphases:\n  build:\n    commands:\n      - make\n"
                    "artifacts:\n  files:\n    - test-*.tgz\n    - test-*.zip\n"
                ),
            },
            "phases": [
                {
                    "phaseType": "DOWNLOAD_SOURCE",
                    "phaseStatus": "SUCCEEDED",
                    "startTime": 11,
                    "endTime": 13,
                },
                {"phaseType": "BUILD", "phaseStatus": "FAILED", "startTime": 15, "endTime": 18},
                {
                    "phaseType": "POST_BUILD",
                    "phaseStatus": "SUCCEEDED",
                    "startTime": 18,
                    "endTime": 20,
                },
                {
                    "phaseType": "UPLOAD_ARTIFACTS",
                    "phaseStatus": "FAILED",
                    "startTime": 20,
                    "endTime": 29,
                    "contexts": [
                        {
                            "statusCode": "CLIENT_ERROR",
                            "message": "no matching artifact paths found",
                        }
                    ],
                },
            ],
        },
        "logs": {
            "build": ID,
            "selection": "[Container] 1970/01/01 00:00:12.001000 YAML location is /codebuild/readonly/buildspec.yml",
            "upload": [
                "[Container] 1970/01/01 00:00:21.000000 Expanding test-*.tgz",
                "[Container] 1970/01/01 00:00:21.100000 Expanding test-*.zip",
                "[Container] 1970/01/01 00:00:21.200000 Set report auto-discover timeout to 5 seconds",
                "[Container] 1970/01/01 00:00:27.000000 Phase complete: UPLOAD_ARTIFACTS State: FAILED",
                "[Container] 1970/01/01 00:00:27.001000 Phase context status code: CLIENT_ERROR Message: no matching artifact paths found",
            ],
        },
        "provider": {"build": ID, "s3Arn": DIRECTORY},
    }


def _write(root, packet):
    capture = root / "receipt.json"
    capture.write_text(json.dumps(packet), encoding="utf-8")
    return capture


def test_no_matches_preserves_source_selection_and_unknown_authority(tmp_path, receipt):
    result = codebuild_s3.codebuild_s3_observation(_write(tmp_path, receipt), tmp_path, ID, ORIGIN)
    assert result["state"] == "primary-artifact-paths-unmatched"
    assert result["head"] == REVISION and result["source_ref"] == "pr/10"
    assert result["publication"] == {
        "operation": "codebuild-managed-s3-artifact-upload",
        "directory_arn": DIRECTORY,
        "selection": "no-matching-primary-paths",
        "authorization": "unverified",
        "service_role_session": "unverified",
    }
    assert result["source_plan"]["artifact_selectors"] == [
        {"path": "test-*.tgz", "line": 8},
        {"path": "test-*.zip", "line": 9},
    ]


@pytest.mark.parametrize(
    "contradiction",
    [
        "other-build",
        "foreign-log",
        "foreign-directory",
        "foreign-directory-suffix",
        "foreign-directory-project",
        "same-repo-different-revision",
        "successful",
        "denied",
        "report-before-selection",
        "build-outside-run",
        "post-build-after-upload",
        "source-out-of-phase",
        "missing-log",
        "secondary-artifact",
        "nested-path",
        "nested-secondary-selector",
        "empty-list-item",
        "empty-map-item",
        "bare-list-item",
    ],
)
def test_empty_primary_profile_rejects_unproven_or_conflicting_cases(
    tmp_path, receipt, contradiction
):
    build, logs, provider = receipt["build"], receipt["logs"], receipt["provider"]
    phases = {phase["phaseType"]: phase for phase in build["phases"]}
    if contradiction == "other-build":
        build["id"] = ID[:-1] + "0"
    elif contradiction == "foreign-log":
        logs["build"] = ID[:-1] + "0"
    elif contradiction == "foreign-directory":
        provider["s3Arn"] = DIRECTORY.replace("abcdef", "abcde0")
    elif contradiction == "foreign-directory-suffix":
        provider["s3Arn"] = DIRECTORY.replace("abcdef", "abcde0") + "/" + ID.split(":")[1]
    elif contradiction == "foreign-directory-project":
        provider["s3Arn"] = DIRECTORY.replace("example", "other-project")
    elif contradiction == "same-repo-different-revision":
        build["resolvedSourceVersion"] = "b" * 40
    elif contradiction == "successful":
        build["buildStatus"] = "SUCCEEDED"
    elif contradiction == "denied":
        phases["UPLOAD_ARTIFACTS"]["contexts"][0]["message"] = "AccessDenied while uploading"
    elif contradiction == "report-before-selection":
        logs["upload"][2] = logs["upload"][2].replace("21.200000", "20.800000")
    elif contradiction == "build-outside-run":
        phases["BUILD"]["endTime"] = 33
    elif contradiction == "post-build-after-upload":
        phases["POST_BUILD"]["endTime"] = 21
    elif contradiction == "source-out-of-phase":
        logs["selection"] = logs["selection"].replace("12.001000", "19.001000")
    elif contradiction == "missing-log":
        logs["upload"].pop()
    elif contradiction == "secondary-artifact":
        build["secondaryArtifacts"] = [{"type": "S3"}]
    elif contradiction == "nested-path":
        build["source"]["buildspec"] = build["source"]["buildspec"].replace(
            "test-*.tgz", "dist/test-*.tgz"
        )
    elif contradiction == "nested-secondary-selector":
        build["source"]["buildspec"] += (
            "  secondary-artifacts:\n    sibling:\n      files: [test-*.zip]\n"
        )
    else:
        entry = {"empty-list-item": "- []", "empty-map-item": "- {}", "bare-list-item": "-"}[
            contradiction
        ]
        build["source"]["buildspec"] += f"    {entry}\n"
    result = codebuild_s3.codebuild_s3_observation(_write(tmp_path, receipt), tmp_path, ID, ORIGIN)
    assert result["state"] == "unresolved"
    assert "publication" not in result
    assert "no matches" not in result["scope"]


def test_cli_renders_selection_without_escalating_coverage(tmp_path, receipt, monkeypatch, capsys):
    capture = _write(tmp_path, receipt)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "taintly",
            str(tmp_path),
            "--no-config",
            "--codebuild-public-s3-observation",
            str(capture),
            ID,
            ORIGIN,
        ],
    )
    with pytest.raises(SystemExit) as exits:
        cli.main()
    assert exits.value.code == 11
    output = capsys.readouterr().out
    assert "reported no matches" in output and "Inline buildspec line 8: test-*.tgz" in output
    assert "remain unverified" in output
