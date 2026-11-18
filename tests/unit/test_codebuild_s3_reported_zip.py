"""Authored controls for a provider-reported CodeBuild ZIP and its evidence boundaries."""

import json
import subprocess

import pytest

from taintly.ingestion.codebuild_s3 import codebuild_s3_observation

ID = "example:01234567-89ab-cdef-0123-456789abcdef"
ORIGIN = "https://github.com/example/project"
TARGET = "arn:aws:s3:::example-bucket/01234567-89ab-cdef-0123-456789abcdef/archive"
BUILDSPEC = (
    "version: 0.2\nphases:\n  build:\n    commands:\n      - bash build.sh\n"
    "artifacts:\n  files:\n    - ${OUTPUT_DIR}/**/*\n  discard-paths: no\n"
)
CHECKSUM = "a" * 64


@pytest.fixture
def receipt(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path).decode().strip()

    git("init", "--quiet")
    git("remote", "add", "origin", ORIGIN)
    (tmp_path / "buildspec.yml").write_text(BUILDSPEC, encoding="utf-8")
    (tmp_path / "build.sh").write_text("printf '%s\\n' test\n", encoding="utf-8")
    git("add", "buildspec.yml", "build.sh")
    git(
        "-c",
        "user.name=Example",
        "-c",
        "user.email=example@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "Fixture",
    )
    return {
        "schema": "codebuild-managed-s3-reported-zip-v1",
        "build": {
            "id": ID,
            "projectName": "example",
            "buildComplete": True,
            "buildStatus": "FAILED",
            "sourceVersion": git("rev-parse", "HEAD"),
            "resolvedSourceVersion": git("rev-parse", "HEAD"),
            "startTime": 10,
            "endTime": 30,
            "environment": {"type": "LINUX_CONTAINER", "environmentVariables": []},
            "secondarySources": [],
            "secondaryArtifacts": [],
            "artifacts": {"type": "S3", "packaging": "ZIP"},
            "source": {"type": "GITHUB", "location": ORIGIN, "buildspec": "buildspec.yml"},
            "phases": [
                {"phaseType": name, "phaseStatus": state, "startTime": t0, "endTime": t1}
                for name, state, t0, t1 in (
                    ("DOWNLOAD_SOURCE", "SUCCEEDED", 11, 13),
                    ("BUILD", "FAILED", 15, 18),
                    ("POST_BUILD", "SUCCEEDED", 18, 20),
                    ("UPLOAD_ARTIFACTS", "SUCCEEDED", 20, 29),
                )
            ],
        },
        "pr": {
            "repository": "example/project",
            "fork": "other/project",
            "number": 42,
            "head": git("rev-parse", "HEAD"),
        },
        "provider": {"build": ID, "s3Arn": TARGET, "sha256Checksum": CHECKSUM},
        "logs": {
            "build": ID,
            "source": (
                "[Container] 1970/01/01 00:00:12.000000 "
                "YAML location is /codebuild/output/src123/src/github.com/Example/Project/buildspec.yml"
            ),
            "command": "[Container] 1970/01/01 00:00:16.000000 Running command bash build.sh",
            "upload": [
                "[Container] 1970/01/01 00:00:21.000000 Expanding ${OUTPUT_DIR}/**/*",
                "[Container] 1970/01/01 00:00:21.100000 Found 4 file(s)",
                "[Container] 1970/01/01 00:00:21.200000 Set report auto-discover timeout to 5 seconds",
                "[Container] 1970/01/01 00:00:27.000000 Phase complete: UPLOAD_ARTIFACTS State: SUCCEEDED",
            ],
        },
    }


def _observe(root, receipt):
    path = root / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return codebuild_s3_observation(path, root, ID, ORIGIN)


@pytest.mark.parametrize("build_status", ["FAILED", "SUCCEEDED"])
def test_reported_zip_binds_source_bytes_and_keeps_authority_unknown(
    tmp_path, receipt, build_status
):
    receipt["build"]["buildStatus"] = receipt["build"]["phases"][1]["phaseStatus"] = build_status
    result = _observe(tmp_path, receipt)
    assert result["state"] == "managed-s3-zip-reported"
    assert result["source_scope"] == "matches-supplied-fork-pr-head"
    assert result["trigger"] == "unverified"
    assert result["build_status"] == build_status
    assert result["source_plan"]["command"]["source"]["revision"] == receipt["pr"]["head"]
    assert result["publication"] == {
        "operation": "codebuild-managed-s3-artifact-upload",
        "object_arn": TARGET,
        "provider_reported_sha256": CHECKSUM,
        "primary_paths_reported": 4,
        "archive_bytes": "unverified",
        "authorization": "unverified",
        "service_role_session": "unverified",
    }


@pytest.mark.parametrize(
    "contrast",
    [
        "unbound-head",
        "wrong-bucket-key",
        "other-build",
        "missing-sha256",
        "report-count",
        "wrong-script",
        "missing-checkout",
        "empty-file-item",
        "upload-denial",
        "secondary",
        "same-repo",
    ],
)
def test_reported_zip_refuses_an_incomplete_join(tmp_path, receipt, contrast):
    if contrast == "unbound-head":
        receipt["pr"]["head"] = "0" * 40
    elif contrast == "wrong-bucket-key":
        receipt["provider"]["s3Arn"] = TARGET.replace("01234567", "61234567")
    elif contrast == "other-build":
        receipt["logs"]["build"] = ID.replace("01234567", "61234567")
    elif contrast == "missing-sha256":
        del receipt["provider"]["sha256Checksum"]
    elif contrast == "report-count":
        receipt["logs"]["upload"][1] = receipt["logs"]["upload"][1].replace("21.100", "22.100")
    elif contrast == "wrong-script":
        receipt["logs"]["command"] = receipt["logs"]["command"].replace("build.sh", "other.sh")
    elif contrast == "missing-checkout":
        del receipt["logs"]["source"]
    elif contrast == "empty-file-item":
        # An empty list item must not pretend to be the supported single-file list.
        (tmp_path / "buildspec.yml").write_text(
            BUILDSPEC.replace("  discard-paths:", "    -\n  discard-paths:"), encoding="utf-8"
        )
        subprocess.run(["git", "add", "buildspec.yml"], cwd=tmp_path, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Example",
                "-c",
                "user.email=example@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "Changed list",
            ],
            cwd=tmp_path,
            check=True,
        )
        revision = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path).decode().strip()
        )
        receipt["build"]["sourceVersion"] = receipt["build"]["resolvedSourceVersion"] = revision
        receipt["pr"]["head"] = revision
    elif contrast == "upload-denial":
        receipt["build"]["phases"][-1]["phaseStatus"] = "FAILED"
    elif contrast == "secondary":
        receipt["build"]["secondaryArtifacts"] = [{"type": "S3"}]
    else:
        receipt["pr"]["fork"] = "EXAMPLE/Project"
    result = _observe(tmp_path, receipt)
    assert result["state"] == "unresolved"
    assert "publication" not in result
